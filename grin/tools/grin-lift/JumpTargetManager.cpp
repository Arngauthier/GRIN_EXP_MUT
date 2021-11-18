/// \file jumptargetmanager.cpp
/// \brief This file handles the possible jump targets encountered during
///        translation and the creation and management of the respective
///        BasicBlock.

//
// This file is distributed under the MIT License. See LICENSE.md for details.
//

// Standard includes
#include "grin/Support/Assert.h"
#include <cstdint>
#include <fstream>
#include <queue>
#include <sstream>

#include <signal.h>
#include <sys/wait.h>

// Boost includes
#include <boost/icl/interval_set.hpp>
#include <boost/icl/right_open_interval.hpp>
#include <boost/type_traits/is_same.hpp>

// LLVM includes
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Endian.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Cloning.h"

// Local libraries includes
#include "grin/ADT/Queue.h"
#include "grin/BasicAnalyses/GeneratedCodeBasicInfo.h"
#include "grin/ReachingDefinitions/ReachingDefinitionsPass.h"
#include "grin/Support/CommandLine.h"
#include "grin/Support/Debug.h"
#include "grin/Support/IRHelpers.h"
#include "grin/Support/grin.h"

// Local includes
#include "JumpTargetManager.h"
#include "SET.h"
#include "SimplifyComparisonsPass.h"
#include "SubGraph.h"

using namespace llvm;

namespace {

Logger<> JTCountLog("jtcount");

cl::opt<bool> Statistics("Statistics",
                         cl::desc("Count rewriting information"),
                         cl::cat(MainCategory));
cl::opt<bool> CFG("CFG", cl::desc("draw CFG"), cl::cat(MainCategory));
cl::opt<bool> BanMultithread("banMultithread",
                             cl::desc("enable multithread"),
                             cl::cat(MainCategory));

cl::opt<bool> DebugChainFiles("debug-chain-files-output",
                              cl::desc("Output file for debugging chains"),
                              cl::cat(MainCategory));

cl::opt<bool> MPCP("multi-process-chains",
                   cl::desc("Run chains with ultiple processes"),
                   cl::cat(MainCategory));

cl::opt<bool> O0("O0",
                 cl::desc("handle binary with O0 optimization"),

                 cl::cat(MainCategory));
cl::opt<bool>
  SUPERFAST("super-fast", cl::desc("fast rewriting"), cl::cat(MainCategory));
cl::opt<bool> VirtualTable("virtual-table",
                           cl::desc("harvest C++ virtual table"),
                           cl::cat(MainCategory));

cl::opt<unsigned int> ProcessNums("process-nums",
                                  cl::desc("the number of child processes"),
                                  cl::init(8),
                                  cl::cat(MainCategory));

cl::opt<unsigned int> LoopNums("loop-nums",
                               cl::desc("the number of loop of each gadget"),
                               cl::init(256),
                               cl::cat(MainCategory));
cl::opt<unsigned int> DCPH("dcph",
                           cl::desc("direct code pointer harvest"),
                           cl::init(256),
                           cl::cat(MainCategory));

cl::opt<bool> NoOSRA("no-osra", cl::desc(" OSRA"), cl::cat(MainCategory));
cl::alias A1("O",
             cl::desc("Alias for -no-osra"),
             cl::aliasopt(NoOSRA),
             cl::cat(MainCategory));

RegisterPass<TranslateDirectBranchesPass> X("translate-db",
                                            "Translate Direct Branches"
                                            " Pass",
                                            false,
                                            false);

// TODO: this is kind of an abuse
Logger<> Verify("verify");
Logger<> RegisterJTLog("registerjt");

} // namespace

char TranslateDirectBranchesPass::ID = 0;

static bool isSumJump(StoreInst *PCWrite);

void TranslateDirectBranchesPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<DominatorTreeWrapperPass>();
  AU.addUsedIfAvailable<SETPass>();
  AU.setPreservesAll();
}

/// \brief Purges everything is after a call to exitTB (except the call itself)
static void exitTBCleanup(Instruction *ExitTBCall) {
  BasicBlock *BB = ExitTBCall->getParent();

  // Cleanup everything it's aftewards starting from the end
  Instruction *ToDelete = &*(--BB->end());
  while (ToDelete != ExitTBCall) {
    if (auto DeadBranch = dyn_cast<BranchInst>(ToDelete))
      purgeBranch(BasicBlock::iterator(DeadBranch));
    else
      ToDelete->eraseFromParent();

    ToDelete = &*(--BB->end());
  }
}

bool TranslateDirectBranchesPass::pinJTs(Function &F) {
  const auto *SET = getAnalysisIfAvailable<SETPass>();
  if (SET == nullptr || SET->jumps().size() == 0)
    return false;

  LLVMContext &Context = getContext(&F);
  Value *PCReg = JTM->pcReg();
  auto *RegType = cast<IntegerType>(PCReg->getType()->getPointerElementType());
  auto C = [RegType](uint64_t A) { return ConstantInt::get(RegType, A); };
  BasicBlock *AnyPC = JTM->anyPC();
  BasicBlock *UnexpectedPC = JTM->unexpectedPC();
  // TODO: enforce CFG

  for (const auto &Jump : SET->jumps()) {
    StoreInst *PCWrite = Jump.Instruction;
    bool Approximate = Jump.Approximate;
    const std::vector<uint64_t> &Destinations = Jump.Destinations;

    // We don't care if we already handled this call too exitTB in the past,
    // information should become progressively more precise, so let's just
    // remove everything after this call and put a new handler
    CallInst *CallExitTB = JTM->findNextExitTB(PCWrite);

    grin_assert(CallExitTB != nullptr);
    grin_assert(PCWrite->getParent()->getParent() == &F);
    grin_assert(JTM->isPCReg(PCWrite->getPointerOperand()));
    grin_assert(Destinations.size() != 0);

    auto *ExitTBArg = ConstantInt::get(Type::getInt32Ty(Context),
                                       Destinations.size());
    uint64_t OldTargetsCount = getLimitedValue(CallExitTB->getArgOperand(0));

    // TODO: we should check Destinations.size() >= OldTargetsCount
    // TODO: we should also check the destinations are actually the same

    BasicBlock *FailBB = Approximate ? AnyPC : UnexpectedPC;
    BasicBlock *BB = CallExitTB->getParent();

    // Kill everything is after the call to exitTB
    exitTBCleanup(CallExitTB);

    // Mark this call to exitTB as handled
    CallExitTB->setArgOperand(0, ExitTBArg);

    IRBuilder<> Builder(BB);
    auto PCLoad = Builder.CreateLoad(PCReg);
    if (Destinations.size() == 1) {
      auto *Comparison = Builder.CreateICmpEQ(C(Destinations[0]), PCLoad);
      Builder.CreateCondBr(Comparison,
                           JTM->getBlockAt(Destinations[0]),
                           FailBB);
    } else {
      auto *Switch = Builder.CreateSwitch(PCLoad, FailBB, Destinations.size());
      for (uint64_t Destination : Destinations)
        Switch->addCase(C(Destination), JTM->getBlockAt(Destination));
    }

    // Move all the markers right before the branch instruction
    Instruction *Last = BB->getTerminator();
    auto It = CallExitTB->getIterator();
    while (isMarker(&*It)) {
      // Get the marker instructions
      Instruction *I = &*It;

      // Move the iterator back
      It--;

      // Move the last moved instruction (initially the terminator)
      I->moveBefore(Last);

      Last = I;
    }

    // Notify new branches only if the amount of possible targets actually
    // increased
    if (Destinations.size() > OldTargetsCount)
      JTM->newBranch();
  }

  return true;
}

bool TranslateDirectBranchesPass::pinConstantStore(Function &F) {
  auto &Context = F.getParent()->getContext();

  Function *ExitTB = JTM->exitTB();
  auto ExitTBIt = ExitTB->use_begin();
  while (ExitTBIt != ExitTB->use_end()) {
    // Take note of the use and increment the iterator immediately: this allows
    // us to erase the call to exit_tb without unexpected behaviors
    Use &ExitTBUse = *ExitTBIt++;
    if (auto Call = dyn_cast<CallInst>(ExitTBUse.getUser())) {
      if (Call->getCalledFunction() == ExitTB) {
        // Look for the last write to the PC
        StoreInst *PCWrite = JTM->getPrevPCWrite(Call);

        // Is destination a constant?
        if (PCWrite == nullptr) {
          // forceFallthroughAfterHelper(Call);
        } else {
          // uint64_t NextPC = JTM->getNextPC(PCWrite);
          // if (NextPC != 0 && not NoOSRA && isSumJump(PCWrite))
          //  JTM->registerJT(NextPC, JTReason::SumJump);

          auto *Address = dyn_cast<ConstantInt>(PCWrite->getValueOperand());
          if (Address != nullptr) {
            // Compute the actual PC and get the associated BasicBlock
            uint64_t TargetPC = Address->getSExtValue();
            if (JTM->isIllegalStaticAddr(TargetPC))
              continue;
            auto *TargetBlock = JTM->obtainJTBB(TargetPC, JTReason::DirectJump);
            if (TargetBlock == nullptr)
              continue;

            // Remove unreachable right after the exit_tb
            BasicBlock::iterator CallIt(Call);
            BasicBlock::iterator BlockEnd = Call->getParent()->end();
            CallIt++;
            grin_assert(CallIt != BlockEnd && isa<UnreachableInst>(&*CallIt));
            CallIt->eraseFromParent();

            // Cleanup of what's afterwards (only a unconditional jump is
            // allowed)
            CallIt = BasicBlock::iterator(Call);
            BlockEnd = Call->getParent()->end();
            if (++CallIt != BlockEnd)
              purgeBranch(CallIt);

            if (TargetBlock != nullptr) {
              // A target was found, jump there
              BranchInst::Create(TargetBlock, Call);
              JTM->newBranch();
            } else {
              // We're jumping to an invalid location, abort everything
              // TODO: emit a warning
              CallInst::Create(F.getParent()->getFunction("abort"), {}, Call);
              new UnreachableInst(Context, Call);
            }
            Call->eraseFromParent();
          }
        }
      } else {
        grin_unreachable("Unexpected instruction using the PC");
      }
    } else {
      grin_unreachable("Unhandled usage of the PC");
    }
  }

  return true;
}

bool TranslateDirectBranchesPass::forceFallthroughAfterHelper(CallInst *Call) {
  // If someone else already took care of the situation, quit
  if (getLimitedValue(Call->getArgOperand(0)) > 0)
    return false;

  auto *PCReg = JTM->pcReg();
  auto PCRegTy = PCReg->getType()->getPointerElementType();
  bool ForceFallthrough = false;

  BasicBlock::reverse_iterator It(++Call->getReverseIterator());
  auto *BB = Call->getParent();
  auto EndIt = BB->rend();
  while (!ForceFallthrough) {
    while (It != EndIt) {
      Instruction *I = &*It;
      if (auto *Store = dyn_cast<StoreInst>(I)) {
        if (Store->getPointerOperand() == PCReg) {
          // We found a PC-store, give up
          return false;
        }
      } else if (auto *Call = dyn_cast<CallInst>(I)) {
        if (Function *Callee = Call->getCalledFunction()) {
          if (Callee->getName().startswith("helper_")) {
            // We found a call to an helper
            ForceFallthrough = true;
            break;
          }
        }
      }
      It++;
    }

    if (!ForceFallthrough) {
      // Proceed only to unique predecessor, if present
      if (auto *Pred = BB->getUniquePredecessor()) {
        BB = Pred;
        It = BB->rbegin();
        EndIt = BB->rend();
      } else {
        // We have multiple predecessors, give up
        return false;
      }
    }
  }

  exitTBCleanup(Call);
  JTM->newBranch();

  IRBuilder<> Builder(Call->getParent());
  Call->setArgOperand(0, Builder.getInt32(1));

  // Create the fallthrough jump
  uint64_t NextPC = JTM->getNextPC(Call);
  Value *NextPCConst = Builder.getIntN(PCRegTy->getIntegerBitWidth(), NextPC);

  // Get the fallthrough basic block and emit a conditional branch, if not
  // possible simply jump to anyPC
  BasicBlock *NextPCBB = JTM->registerJT(NextPC, JTReason::PostHelper);
  if (NextPCBB != nullptr) {
    Builder.CreateCondBr(Builder.CreateICmpEQ(Builder.CreateLoad(PCReg),
                                              NextPCConst),
                         NextPCBB,
                         JTM->anyPC());
  } else {
    Builder.CreateBr(JTM->anyPC());
  }

  return true;
}

bool TranslateDirectBranchesPass::runOnModule(Module &M) {
  Function &F = *M.getFunction("root");
  pinConstantStore(F);
  // pinJTs(F);
  return true;
}

uint64_t TranslateDirectBranchesPass::getNextPC(Instruction *TheInstruction) {
  DominatorTree &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();

  BasicBlock *Block = TheInstruction->getParent();
  BasicBlock::reverse_iterator It(++TheInstruction->getReverseIterator());

  while (true) {
    BasicBlock::reverse_iterator Begin(Block->rend());

    // Go back towards the beginning of the basic block looking for a call to
    // newpc
    CallInst *Marker = nullptr;
    for (; It != Begin; It++) {
      if ((Marker = dyn_cast<CallInst>(&*It))) {
        // TODO: comparing strings is not very elegant
        if (Marker->getCalledFunction()->getName() == "newpc") {
          uint64_t PC = getLimitedValue(Marker->getArgOperand(0));
          uint64_t Size = getLimitedValue(Marker->getArgOperand(1));
          grin_assert(Size != 0);
          return PC + Size;
        }
      }
    }

    auto *Node = DT.getNode(Block);
    grin_assert(Node != nullptr,
                "BasicBlock not in the dominator tree, is it reachable?");

    Block = Node->getIDom()->getBlock();
    It = Block->rbegin();
  }

  grin_unreachable("Can't find the PC marker");
}

Constant *JumpTargetManager::readConstantPointer(Constant *Address,
                                                 Type *PointerTy,
                                                 BinaryFile::Endianess E) {
  Constant *ConstInt = readConstantInt(Address,
                                       Binary.architecture().pointerSize() / 8,
                                       E);
  if (ConstInt != nullptr) {
    return Constant::getIntegerValue(PointerTy, ConstInt->getUniqueInteger());
  } else {
    return nullptr;
  }
}

ConstantInt *JumpTargetManager::readConstantInt(Constant *ConstantAddress,
                                                unsigned Size,
                                                BinaryFile::Endianess E) {
  const DataLayout &DL = TheModule.getDataLayout();

  if (ConstantAddress->getType()->isPointerTy()) {
    using CE = ConstantExpr;
    auto IntPtrTy = Type::getIntNTy(Context,
                                    Binary.architecture().pointerSize());
    ConstantAddress = CE::getPtrToInt(ConstantAddress, IntPtrTy);
  }

  uint64_t Address = getZExtValue(ConstantAddress, DL);
  UnusedCodePointers.erase(Address);
  registerReadRange(Address, Size);

  auto Result = Binary.readRawValue(Address, Size, E);

  if (Result.hasValue())
    return ConstantInt::get(IntegerType::get(Context, Size * 8),
                            Result.getValue());
  else
    return nullptr;
}

template<typename T>
static cl::opt<T> *
getOption(StringMap<cl::Option *> &Options, const char *Name) {
  return static_cast<cl::opt<T> *>(Options[Name]);
}

JumpTargetManager::JumpTargetManager(Function *TheFunction,
                                     Value *PCReg,
                                     const BinaryFile &Binary) :
  TheModule(*TheFunction->getParent()),
  Context(TheModule.getContext()),
  TheFunction(TheFunction),
  OriginalInstructionAddresses(),
  JumpTargets(),
  assign_gadge(),
  PCReg(PCReg),
  ExitTB(nullptr),
  Dispatcher(nullptr),
  DispatcherSwitch(nullptr),
  Binary(Binary),
  NoReturn(Binary.architecture()),
  CurrentCFGForm(CFGForm::UnknownFormCFG) {
  FunctionType *ExitTBTy = FunctionType::get(Type::getVoidTy(Context),
                                             { Type::getInt32Ty(Context) },
                                             false);
  ExitTB = cast<Function>(TheModule.getOrInsertFunction("exitTB", ExitTBTy));
  createDispatcher(TheFunction, PCReg);

  for (auto &Segment : Binary.segments()) {
    Segment.insertExecutableRanges(std::back_inserter(ExecutableRanges));
    if (Segment.IsExecutable) {
      codeSeg_StartAddr = Segment.StartVirtualAddress;
    }
    if (Segment.IsWriteable and !Segment.IsExecutable) {
      DataSegmStartAddr = Segment.StartVirtualAddress;
      DataSegmEndAddr = Segment.EndVirtualAddress;
    }
  }
  ro_StartAddr = 0;
  ro_EndAddr = 0;
  text_StartAddr = 0;
  if (Binary.rodataStartAddr) {
    ro_StartAddr = Binary.rodataStartAddr;
    ro_EndAddr = Binary.ehframeEndAddr;
    grin_assert(ro_StartAddr <= ro_EndAddr);
  }
  if (Binary.textStartAddr)
    text_StartAddr = Binary.textStartAddr;

  // Configure GlobalValueNumbering
  StringMap<cl::Option *> &Options(cl::getRegisteredOptions());
  getOption<bool>(Options, "enable-load-pre")->setInitialValue(false);
  getOption<unsigned>(Options, "memdep-block-scan-limit")->setInitialValue(100);
  // getOption<bool>(Options, "enable-pre")->setInitialValue(false);
  // getOption<uint32_t>(Options, "max-recurse-depth")->setInitialValue(10);
  haveBB = 0;
  elf_name = nullptr;
  range = 0;
  BlockBound = 0;
  isRecordCandidataAddr = false;
  outputpath = "";
}

JumpTargetManager::JumpTargetManager(Function *TheFunction,
                                     Value *PCReg,
                                     const BinaryFile &Binary,
                                     GlobalVariable *ELFName) :
  TheModule(*TheFunction->getParent()),
  Context(TheModule.getContext()),
  TheFunction(TheFunction),
  OriginalInstructionAddresses(),
  JumpTargets(),
  assign_gadge(),
  PCReg(PCReg),
  ExitTB(nullptr),
  Dispatcher(nullptr),
  DispatcherSwitch(nullptr),
  Binary(Binary),
  NoReturn(Binary.architecture()),
  CurrentCFGForm(CFGForm::UnknownFormCFG) {
  FunctionType *ExitTBTy = FunctionType::get(Type::getVoidTy(Context),
                                             { Type::getInt32Ty(Context) },
                                             false);
  elf_name = ELFName;
  ExitTB = cast<Function>(TheModule.getOrInsertFunction("exitTB", ExitTBTy));
  createDispatcher(TheFunction, PCReg);

  for (auto &Segment : Binary.segments()) {
    Segment.insertExecutableRanges(std::back_inserter(ExecutableRanges));
    if (Segment.IsExecutable) {
      codeSeg_StartAddr = Segment.StartVirtualAddress;
    }
    if (Segment.IsWriteable and !Segment.IsExecutable) {
      DataSegmStartAddr = Segment.StartVirtualAddress;
      DataSegmEndAddr = Segment.EndVirtualAddress;
    }
  }
  ro_StartAddr = 0;
  ro_EndAddr = 0;
  text_StartAddr = 0;
  if (Binary.rodataStartAddr) {
    ro_StartAddr = Binary.rodataStartAddr;
    ro_EndAddr = Binary.ehframeEndAddr;
    grin_assert(ro_StartAddr <= ro_EndAddr);
  }
  if (Binary.textStartAddr)
    text_StartAddr = Binary.textStartAddr;

  // Configure GlobalValueNumbering
  StringMap<cl::Option *> &Options(cl::getRegisteredOptions());
  getOption<bool>(Options, "enable-load-pre")->setInitialValue(false);
  getOption<unsigned>(Options, "memdep-block-scan-limit")->setInitialValue(100);
  // getOption<bool>(Options, "enable-pre")->setInitialValue(false);
  // getOption<uint32_t>(Options, "max-recurse-depth")->setInitialValue(10);
  haveBB = 0;
  range = 0;
  BlockBound = 0;
  isRecordCandidataAddr = false;
  outputpath = "";
}

static bool isBetterThan(const Label *NewCandidate, const Label *OldCandidate) {
  if (OldCandidate == nullptr)
    return true;

  if (NewCandidate->address() > OldCandidate->address())
    return true;

  if (NewCandidate->address() == OldCandidate->address()) {
    StringRef OldName = OldCandidate->symbolName();
    if (OldName.size() == 0)
      return true;
  }

  return false;
}

// TODO: move this in BinaryFile?
std::string
JumpTargetManager::nameForAddress(uint64_t Address, uint64_t Size) const {
  std::stringstream Result;
  const auto &SymbolMap = Binary.labels();

  auto It = SymbolMap.find(interval::right_open(Address, Address + Size));
  if (It != SymbolMap.end()) {
    // We have to look for (in order):
    //
    // * Exact match
    // * Contained (non 0-sized)
    // * Contained (0-sized)
    const Label *ExactMatch = nullptr;
    const Label *ContainedNonZeroSized = nullptr;
    const Label *ContainedZeroSized = nullptr;

    for (const Label *L : It->second) {
      // Consider symbols only
      if (not L->isSymbol())
        continue;

      if (L->matches(Address, Size)) {

        // It's an exact match
        ExactMatch = L;
        break;

      } else if (not L->isSizeVirtual() and L->contains(Address, Size)) {

        // It's contained in a not 0-sized symbol
        if (isBetterThan(L, ContainedNonZeroSized))
          ContainedNonZeroSized = L;

      } else if (L->isSizeVirtual() and L->contains(Address, 0)) {

        // It's contained in a 0-sized symbol
        if (isBetterThan(L, ContainedZeroSized))
          ContainedZeroSized = L;
      }
    }

    const Label *Chosen = nullptr;
    if (ExactMatch != nullptr)
      Chosen = ExactMatch;
    else if (ContainedNonZeroSized != nullptr)
      Chosen = ContainedNonZeroSized;
    else if (ContainedZeroSized != nullptr)
      Chosen = ContainedZeroSized;

    if (Chosen != nullptr and Chosen->symbolName().size() != 0) {
      // Use the symbol name
      Result << Chosen->symbolName().str();

      // And, if necessary, an offset
      if (Address != Chosen->address())
        Result << ".0x" << std::hex << (Address - Chosen->address());

      return Result.str();
    }
  }

  // We don't have a symbol to use, just return the address
  Result << "0x" << std::hex << Address;
  return Result.str();
}

void JumpTargetManager::harvestGlobalData() {
  // Register symbols
  for (auto &P : Binary.labels())
    for (const Label *L : P.second)
      if (L->isSymbol() and L->isCode())
        registerJT(L->address(), JTReason::FunctionSymbol);

  // Register landing pads, if available
  // TODO: should register them in UnusedCodePointers?
  for (uint64_t LandingPad : Binary.landingPads())
    registerJT(LandingPad, JTReason::GlobalData);

  for (uint64_t CodePointer : Binary.codePointers())
    registerJT(CodePointer, JTReason::GlobalData);

  for (auto &Segment : Binary.segments()) {
    const Constant *Initializer = Segment.Variable->getInitializer();
    if (isa<ConstantAggregateZero>(Initializer))
      continue;

    auto *Data = cast<ConstantDataArray>(Initializer);
    uint64_t StartVirtualAddress = Segment.StartVirtualAddress;
    const unsigned char *DataStart = Data->getRawDataValues().bytes_begin();
    const unsigned char *DataEnd = Data->getRawDataValues().bytes_end();

    using endianness = support::endianness;
    if (Binary.architecture().pointerSize() == 64) {
      if (Binary.architecture().isLittleEndian())
        findCodePointers<uint64_t, endianness::little>(StartVirtualAddress,
                                                       DataStart,
                                                       DataEnd);
      else
        findCodePointers<uint64_t, endianness::big>(StartVirtualAddress,
                                                    DataStart,
                                                    DataEnd);
    } else if (Binary.architecture().pointerSize() == 32) {
      if (Binary.architecture().isLittleEndian())
        findCodePointers<uint32_t, endianness::little>(StartVirtualAddress,
                                                       DataStart,
                                                       DataEnd);
      else
        findCodePointers<uint32_t, endianness::big>(StartVirtualAddress,
                                                    DataStart,
                                                    DataEnd);
    }
  }

  grin_log(JTCountLog,
           "JumpTargets found in global data: " << std::dec
                                                << Unexplored.size());
}

template<typename value_type, unsigned endian>
void JumpTargetManager::findCodePointers(uint64_t StartVirtualAddress,
                                         const unsigned char *Start,
                                         const unsigned char *End) {
  using support::endianness;
  using support::endian::read;
  for (auto Pos = Start; Pos < End - sizeof(value_type); Pos++) {
    uint64_t Value = read<value_type, static_cast<endianness>(endian), 1>(Pos);
    BasicBlock *Result = registerJT(Value, JTReason::GlobalData);

    if (Result != nullptr)
      UnusedCodePointers.insert(StartVirtualAddress + (Pos - Start));
  }
}

/// Handle a new program counter. We might already have a basic block for that
/// program counter, or we could even have a translation for it. Return one of
/// these, if appropriate.
///
/// \param PC the new program counter.
/// \param ShouldContinue an out parameter indicating whether the returned
///        basic block was just a placeholder or actually contains a
///        translation.
///
/// \return the basic block to use from now on, or null if the program counter
///         is not associated to a basic block.
// TODO: make this return a pair
BasicBlock *JumpTargetManager::newPC(uint64_t PC, bool &ShouldContinue) {
  // Did we already meet this PC?
  auto JTIt = JumpTargets.find(PC);
  if (JTIt != JumpTargets.end()) {
    // If it was planned to explore it in the future, just to do it now
    for (auto UnexploredIt = Unexplored.begin();
         UnexploredIt != Unexplored.end();
         UnexploredIt++) {

      if (UnexploredIt->first == PC) {
        BasicBlock *Result = UnexploredIt->second;

        // Check if we already have a translation for that
        ShouldContinue = Result->empty();
        if (ShouldContinue) {
          // We don't, OK let's explore it next
          Unexplored.erase(UnexploredIt);
        } else {
          // We do, it will be purged at the next `peek`
          grin_assert(ToPurge.count(Result) != 0);
        }

        return Result;
      }
    }

    // It wasn't planned to visit it, so we've already been there, just jump
    // there
    BasicBlock *BB = JTIt->second.head();
    grin_assert(!BB->empty());
    ShouldContinue = false;
    return BB;
  }

  // Check if we already translated this PC even if it's not associated to a
  // basic block (i.e., we have to split its basic block). This typically
  // happens with variable-length instruction encodings.
  if (OriginalInstructionAddresses.count(PC) != 0) {
    ShouldContinue = false;
    InstructionMap::iterator InstrIt = OriginalInstructionAddresses.find(PC);
    Instruction *I = InstrIt->second;
    haveBB = 1;
    return I->getParent();
    // grin_abort("Why this?\n");
    // return registerJT(PC, JTReason::AmbigousInstruction);
  }

  // We don't know anything about this PC
  return nullptr;
}

/// Save the PC-Instruction association for future use (jump target)
void JumpTargetManager::registerInstruction(uint64_t PC,
                                            Instruction *Instruction) {
  // Never save twice a PC
  grin_assert(!OriginalInstructionAddresses.count(PC));
  OriginalInstructionAddresses[PC] = Instruction;
}

CallInst *JumpTargetManager::findNextExitTB(Instruction *Start) {

  struct Visitor
    : public BFSVisitorBase<true, Visitor, SmallVector<BasicBlock *, 4>> {
  public:
    using SuccessorsType = SmallVector<BasicBlock *, 4>;

  public:
    CallInst *Result;
    Function *ExitTB;
    JumpTargetManager *JTM;

  public:
    Visitor(Function *ExitTB, JumpTargetManager *JTM) :
      Result(nullptr),
      ExitTB(ExitTB),
      JTM(JTM) {}

  public:
    VisitAction visit(BasicBlockRange Range) {
      for (Instruction &I : Range) {
        if (auto *Call = dyn_cast<CallInst>(&I)) {
          grin_assert(!(Call->getCalledFunction()->getName() == "newpc"));
          if (Call->getCalledFunction() == ExitTB) {
            grin_assert(Result == nullptr);
            Result = Call;
            return ExhaustQueueAndStop;
          }
        }
      }

      return Continue;
    }

    SuccessorsType successors(BasicBlock *BB) {
      SuccessorsType Successors;
      for (BasicBlock *Successor : make_range(succ_begin(BB), succ_end(BB)))
        if (JTM->isTranslatedBB(Successor))
          Successors.push_back(Successor);
      return Successors;
    }
  };

  Visitor V(ExitTB, this);
  V.run(Start);

  return V.Result;
}

StoreInst *JumpTargetManager::getPrevPCWrite(Instruction *TheInstruction) {
  // Look for the last write to the PC
  BasicBlock::iterator I(TheInstruction);
  BasicBlock::iterator Begin(TheInstruction->getParent()->begin());

  while (I != Begin) {
    I--;
    Instruction *Current = &*I;

    auto *Store = dyn_cast<StoreInst>(Current);
    if (Store != nullptr && Store->getPointerOperand() == PCReg)
      return Store;

    // If we meet a call to an helper, return nullptr
    // TODO: for now we just make calls to helpers, is this is OK even if we
    //       split the translated function in multiple functions?
    if (isa<CallInst>(Current))
      return nullptr;
  }

  // TODO: handle the following case:
  //          pc = x
  //          brcond ?, a, b
  //       a:
  //          pc = y
  //          br b
  //       b:
  //          exitTB
  // TODO: emit warning
  return nullptr;
}

// TODO: this is outdated and we should drop it, we now have OSRA and friends
/// \brief Tries to detect pc += register In general, we assume what we're
/// translating is code emitted by a compiler. This means that usually all the
/// possible jump targets are explicit jump to a constant or are stored
/// somewhere in memory (e.g.  jump tables and vtables). However, in certain
/// cases, mainly due to handcrafted assembly we can have a situation like the
/// following:
///
///     addne pc, pc, \\curbit, lsl #2
///
/// (taken from libgcc ARM's lib1funcs.S, specifically line 592 of
/// `libgcc/config/arm/lib1funcs.S` at commit
/// `f1717362de1e56fe1ffab540289d7d0c6ed48b20`)
///
/// This code basically jumps forward a number of instructions depending on a
/// run-time value. Therefore, without further analysis, potentially, all the
/// coming instructions are jump targets.
///
/// To workaround this issue we use a simple heuristics, which basically
/// consists in making all the coming instructions possible jump targets until
/// the next write to the PC. In the future, we could extend this until the end
/// of the function.
static bool isSumJump(StoreInst *PCWrite) {
  // * Follow the written value recursively
  //   * Is it a `load` or a `constant`? Fine. Don't proceed.
  //   * Is it an `and`? Enqueue the operands in the worklist.
  //   * Is it an `add`? Make all the coming instructions jump targets.
  //
  // This approach has a series of problems:
  //
  // * It doesn't work with delay slots. Delay slots are handled by libtinycode
  //   as follows:
  //
  //       jump lr
  //         store btarget, lr
  //       store 3, r0
  //         store 3, r0
  //         store btarget, pc
  //
  //   Clearly, if we don't follow the loads we miss the situation we're trying
  //   to handle.
  // * It is unclear how this would perform without EarlyCSE and SROA.
  std::queue<Value *> WorkList;
  WorkList.push(PCWrite->getValueOperand());

  while (!WorkList.empty()) {
    Value *V = WorkList.front();
    WorkList.pop();

    if (isa<Constant>(V) || isa<LoadInst>(V)) {
      // Fine
    } else if (auto *BinOp = dyn_cast<BinaryOperator>(V)) {
      switch (BinOp->getOpcode()) {
      case Instruction::Add:
      case Instruction::Or:
        return true;
      case Instruction::Shl:
      case Instruction::LShr:
      case Instruction::AShr:
      case Instruction::And:
        for (auto &Operand : BinOp->operands())
          if (!isa<Constant>(Operand.get()))
            WorkList.push(Operand.get());
        break;
      default:
        // TODO: emit warning
        return false;
      }
    } else {
      // TODO: emit warning
      return false;
    }
  }

  return false;
}

std::pair<uint64_t, uint64_t>
JumpTargetManager::getPC(Instruction *TheInstruction) const {
  CallInst *NewPCCall = nullptr;
  std::set<BasicBlock *> Visited;
  std::queue<BasicBlock::reverse_iterator> WorkList;
  if (TheInstruction->getIterator() == TheInstruction->getParent()->begin())
    WorkList.push(--TheInstruction->getParent()->rend());
  else
    WorkList.push(++TheInstruction->getReverseIterator());

  while (!WorkList.empty()) {
    auto I = WorkList.front();
    WorkList.pop();
    auto *BB = I->getParent();
    auto End = BB->rend();

    // Go through the instructions looking for calls to newpc
    for (; I != End; I++) {
      if (auto Marker = dyn_cast<CallInst>(&*I)) {
        // TODO: comparing strings is not very elegant
        auto *Callee = Marker->getCalledFunction();
        if (Callee != nullptr && Callee->getName() == "newpc") {

          // We found two distinct newpc leading to the requested instruction
          if (NewPCCall != nullptr)
            return { 0, 0 };

          NewPCCall = Marker;
          break;
        }
      }
    }

    // If we haven't find a newpc call yet, continue exploration backward
    if (NewPCCall == nullptr) {
      // If one of the predecessors is the dispatcher, don't explore any further
      for (BasicBlock *Predecessor : predecessors(BB)) {
        // Assert we didn't reach the almighty dispatcher
        grin_assert(!(NewPCCall == nullptr && Predecessor == Dispatcher));
        if (Predecessor == Dispatcher)
          continue;
      }

      for (BasicBlock *Predecessor : predecessors(BB)) {
        // Ignore already visited or empty BBs
        if (!Predecessor->empty()
            && Visited.find(Predecessor) == Visited.end()) {
          WorkList.push(Predecessor->rbegin());
          Visited.insert(Predecessor);
        }
      }
    }
  }

  // Couldn't find the current PC
  if (NewPCCall == nullptr)
    return { 0, 0 };

  uint64_t PC = getLimitedValue(NewPCCall->getArgOperand(0));
  uint64_t Size = getLimitedValue(NewPCCall->getArgOperand(1));
  grin_assert(Size != 0);
  return { PC, Size };
}

void JumpTargetManager::handleSumJump(Instruction *SumJump) {
  // Take the next PC
  uint64_t NextPC = getNextPC(SumJump);
  grin_assert(NextPC != 0);
  BasicBlock *BB = registerJT(NextPC, JTReason::SumJump);
  grin_assert(BB && !BB->empty());

  std::set<BasicBlock *> Visited;
  Visited.insert(Dispatcher);
  std::queue<BasicBlock *> WorkList;
  WorkList.push(BB);
  while (!WorkList.empty()) {
    BB = WorkList.front();
    Visited.insert(BB);
    WorkList.pop();

    BasicBlock::iterator I(BB->begin());
    BasicBlock::iterator End(BB->end());
    while (I != End) {
      // Is it a new PC marker?
      if (auto *Call = dyn_cast<CallInst>(&*I)) {
        Function *Callee = Call->getCalledFunction();
        // TODO: comparing strings is not very elegant
        if (Callee != nullptr && Callee->getName() == "newpc") {
          uint64_t PC = getLimitedValue(Call->getArgOperand(0));

          // If we've found a (direct or indirect) jump, stop
          if (PC != NextPC)
            return;

          // Split and update iterators to proceed
          BB = registerJT(PC, JTReason::SumJump);

          // Do we have a block?
          if (BB == nullptr)
            return;

          I = BB->begin();
          End = BB->end();

          // Updated the expectation for the next PC
          NextPC = PC + getLimitedValue(Call->getArgOperand(1));
        } else if (Call->getCalledFunction() == ExitTB) {
          // We've found an unparsed indirect jump
          return;
        }
      }

      // Proceed to next instruction
      I++;
    }

    // Inspect and enqueue successors
    for (BasicBlock *Successor : successors(BB))
      if (Visited.find(Successor) == Visited.end())
        WorkList.push(Successor);
  }
}

/// \brief Class to iterate over all the BBs associated to a translated PC
class BasicBlockVisitor {
public:
  BasicBlockVisitor(const SwitchInst *Dispatcher) :
    Dispatcher(Dispatcher),
    JumpTargetIndex(0),
    JumpTargetsCount(Dispatcher->getNumSuccessors()),
    DL(Dispatcher->getParent()->getParent()->getParent()->getDataLayout()) {}

  void enqueue(BasicBlock *BB) {
    if (Visited.count(BB))
      return;
    Visited.insert(BB);

    uint64_t PC = getPC(BB);
    if (PC == 0)
      SamePC.push(BB);
    else
      NewPC.push({ BB, PC });
  }

  // TODO: this function assumes 0 is not a valid PC
  std::pair<BasicBlock *, uint64_t> pop() {
    if (!SamePC.empty()) {
      auto Result = SamePC.front();
      SamePC.pop();
      return { Result, 0 };
    } else if (!NewPC.empty()) {
      auto Result = NewPC.front();
      NewPC.pop();
      return Result;
    } else if (JumpTargetIndex < JumpTargetsCount) {
      BasicBlock *BB = Dispatcher->getSuccessor(JumpTargetIndex);
      JumpTargetIndex++;
      return { BB, getPC(BB) };
    } else {
      return { nullptr, 0 };
    }
  }

private:
  // TODO: this function assumes 0 is not a valid PC
  uint64_t getPC(BasicBlock *BB) {
    if (!BB->empty()) {
      if (auto *Call = dyn_cast<CallInst>(&*BB->begin())) {
        Function *Callee = Call->getCalledFunction();
        // TODO: comparing with "newpc" string is sad
        if (Callee != nullptr && Callee->getName() == "newpc") {
          Constant *PCOperand = cast<Constant>(Call->getArgOperand(0));
          return getZExtValue(PCOperand, DL);
        }
      }
    }

    return 0;
  }

private:
  const SwitchInst *Dispatcher;
  unsigned JumpTargetIndex;
  unsigned JumpTargetsCount;
  const DataLayout &DL;
  std::set<BasicBlock *> Visited;
  std::queue<BasicBlock *> SamePC;
  std::queue<std::pair<BasicBlock *, uint64_t>> NewPC;
};

void JumpTargetManager::translateIndirectJumps() {
  if (ExitTB->use_empty())
    return;

  legacy::PassManager AnalysisPM;
  AnalysisPM.add(new TranslateDirectBranchesPass(this));
  AnalysisPM.run(TheModule);

  auto I = ExitTB->use_begin();

  while (I != ExitTB->use_end()) {
    Use &ExitTBUse = *I++;

    if (auto *Call = dyn_cast<CallInst>(ExitTBUse.getUser())) {
      if (Call->getCalledFunction() == ExitTB) {
        // Look for the last write to the PC
        StoreInst *PCWrite = getPrevPCWrite(Call);
        if (PCWrite != nullptr) {
          //   grin_assert(!isa<ConstantInt>(PCWrite->getValueOperand()),
          //               "Direct jumps should not be handled here");
        }

        if (PCWrite != nullptr && not NoOSRA && isSumJump(PCWrite))
          handleSumJump(PCWrite);

        if (getLimitedValue(Call->getArgOperand(0)) == 0) {
          exitTBCleanup(Call);
          BranchInst::Create(Dispatcher, Call);
        }

        // BasicBlock::iterator Begin1(Call->getParent()->begin());
        // BasicBlock * Begin1(Call->getParent());
        // errs()<<*Begin1<<"\n";

        Call->eraseFromParent();
      }
    }
  }

  grin_assert(ExitTB->use_empty());
  ExitTB->eraseFromParent();
  ExitTB = nullptr;
}

JumpTargetManager::BlockWithAddress JumpTargetManager::peek() {
  harvest();

  // Purge all the partial translations we know might be wrong
  for (BasicBlock *BB : ToPurge)
    purgeTranslation(BB);
  ToPurge.clear();

  if (Unexplored.empty())
    return NoMoreTargets;
  else {
    BlockWithAddress Result = Unexplored.back();
    Unexplored.pop_back();
    return Result;
  }
}

void JumpTargetManager::unvisit(BasicBlock *BB) {
  if (Visited.find(BB) != Visited.end()) {
    std::vector<BasicBlock *> WorkList;
    WorkList.push_back(BB);

    while (!WorkList.empty()) {
      BasicBlock *Current = WorkList.back();
      WorkList.pop_back();

      Visited.erase(Current);

      for (BasicBlock *Successor : successors(BB)) {
        if (Visited.find(Successor) != Visited.end() && !Successor->empty()) {
          auto *Call = dyn_cast<CallInst>(&*Successor->begin());
          if (Call == nullptr
              || Call->getCalledFunction()->getName() != "newpc") {
            WorkList.push_back(Successor);
          }
        }
      }
    }
  }
}

BasicBlock *JumpTargetManager::getBlockAt(uint64_t PC) {
  auto TargetIt = JumpTargets.find(PC);
  grin_assert(TargetIt != JumpTargets.end());
  return TargetIt->second.head();
}

void JumpTargetManager::purgeTranslation(BasicBlock *Start) {
  OnceQueue<BasicBlock *> Queue;
  Queue.insert(Start);

  // Collect all the descendats, except if we meet a jump target
  while (!Queue.empty()) {
    BasicBlock *BB = Queue.pop();
    for (BasicBlock *Successor : successors(BB)) {
      if (isTranslatedBB(Successor) && !isJumpTarget(Successor)
          && !hasPredecessor(Successor, Dispatcher)) {
        Queue.insert(Successor);
      }
    }
  }

  // Erase all the visited basic blocks
  std::set<BasicBlock *> Visited = Queue.visited();

  // Build a subgraph, so that we can visit it in post order, and purge the
  // content of each basic block
  SubGraph<BasicBlock *> TranslatedBBs(Start, Visited);
  for (auto *Node : post_order(TranslatedBBs)) {
    BasicBlock *BB = Node->get();
    while (!BB->empty())
      eraseInstruction(&*(--BB->end()));
  }

  // Remove Start, since we want to keep it (even if empty)
  Visited.erase(Start);

  for (BasicBlock *BB : Visited) {
    // We might have some predecessorless basic blocks jumping to us, purge them
    // TODO: why this?
    while (pred_begin(BB) != pred_end(BB)) {
      BasicBlock *Predecessor = *pred_begin(BB);
      // grin_assert(pred_empty(Predecessor));
      Predecessor->eraseFromParent();
    }

    grin_assert(BB->use_empty());
    BB->eraseFromParent();
  }
}

void JumpTargetManager::purgeIllegalTranslation(llvm::BasicBlock *thisBlock) {
  while ((--(--thisBlock->end())) != thisBlock->begin())
    eraseInstruction(&*(--(--thisBlock->end())));
  if (dyn_cast<BranchInst>(--thisBlock->end())) {
    eraseInstruction(&*(--thisBlock->end()));
    CallInst::Create(TheModule.getFunction("abort"), {}, thisBlock);
    new UnreachableInst(Context, thisBlock);
  }
  eraseInstruction(&*(thisBlock->begin()));
}

BasicBlock *
JumpTargetManager::obtainJTBB(uint64_t PC, JTReason::Values Reason) {

  BlockMap::iterator TargetIt = JumpTargets.find(PC);
  if (TargetIt != JumpTargets.end()) {
    // Case 1: there's already a BasicBlock for that address, return it
    BasicBlock *BB = TargetIt->second.head();
    TargetIt->second.setReason(Reason);

    unvisit(BB);
    return BB;
  }
  return nullptr;
}

BasicBlock *JumpTargetManager::obtainJTBB(uint64_t PC) {

  BlockMap::iterator TargetIt = JumpTargets.find(PC);
  if (TargetIt != JumpTargets.end()) {
    BasicBlock *BB = TargetIt->second.head();
    return BB;
  }
  return nullptr;
}

// TODO: register Reason
BasicBlock *
JumpTargetManager::registerJT(uint64_t PC, JTReason::Values Reason) {
  haveBB = 0;
  if (!isExecutableAddress(PC) || !isInstructionAligned(PC))
    return nullptr;

  grin_log(RegisterJTLog,
           "Registering bb." << nameForAddress(PC) << " for "
                             << JTReason::getName(Reason));

  // Do we already have a BasicBlock for this PC?
  BlockMap::iterator TargetIt = JumpTargets.find(PC);
  if (TargetIt != JumpTargets.end()) {
    // Case 1: there's already a BasicBlock for that address, return it
    BasicBlock *BB = TargetIt->second.head();
    TargetIt->second.setReason(Reason);

    haveBB = 1;

    unvisit(BB);
    return BB;
  }

  // Did we already meet this PC (i.e. do we know what's the associated
  // instruction)?
  BasicBlock *NewBlock = nullptr;
  InstructionMap::iterator InstrIt = OriginalInstructionAddresses.find(PC);
  if (InstrIt != OriginalInstructionAddresses.end()) {
    // Case 2: the address has already been met, but needs to be promoted to
    //         BasicBlock level.
    Instruction *I = InstrIt->second;
    BasicBlock *ContainingBlock = I->getParent();
    if (isFirst(I)) {
      NewBlock = ContainingBlock;
    } else {
      grin_assert(I != nullptr && I->getIterator() != ContainingBlock->end());

      std::map<llvm::BasicBlock *, uint32_t>::iterator TargetG = AllGadget.find(
        ContainingBlock);
      std::map<llvm::BasicBlock *, uint32_t>::iterator
        TargetS = AllStaticGadget.find(ContainingBlock);
      if (TargetG != AllGadget.end() or TargetS != AllStaticGadget.end()) {
        for (auto &g : assign_gadge) {
          if (g.second.operation_block == ContainingBlock
              or g.second.static_addr_block == ContainingBlock) {
            if (getPosition(I) <= getPosition(g.second.global_I)) {
              g.second.operation_block = nullptr;
              g.second.static_addr_block = nullptr;
              g.second.global_I = nullptr;
              g.second.static_global_I = nullptr;
            }
          }
        }
        // AllGadget.erase(ContainingBlock);
        // AllStaticGadget.erase(ContainingBlock);
      }

      NewBlock = ContainingBlock->splitBasicBlock(I);
    }

    // Register the basic block and all of its descendants to be purged so that
    // we can retranslate this PC
    // TODO: this might create a problem if QEMU generates control flow that
    //       crosses an instruction boundary
    ToPurge.insert(NewBlock);

    unvisit(NewBlock);
  } else {
    // Case 3: the address has never been met, create a temporary one, register
    // it for future exploration and return it
    NewBlock = BasicBlock::Create(Context, "", TheFunction);
  }

  Unexplored.push_back(BlockWithAddress(PC, NewBlock));

  std::stringstream Name;
  Name << "bb." << nameForAddress(PC);
  NewBlock->setName(Name.str());

  // Create a case for the address associated to the new block
  auto *PCRegType = PCReg->getType();
  auto *SwitchType = cast<IntegerType>(PCRegType->getPointerElementType());
  auto a = ConstantInt::get(SwitchType, PC);
  DispatcherSwitch->addCase(a, NewBlock);

  // Associate the PC with the chosen basic block
  JumpTargets[PC] = JumpTarget(NewBlock, Reason);
  return NewBlock;
}

size_t JumpTargetManager::getPosition(llvm::Instruction *I) {
  if (I == nullptr)
    return 1;
  BasicBlock::iterator it(I->getParent()->begin());
  BasicBlock::iterator end(I->getParent()->end());

  size_t n = 1;
  for (; it != end; it++) {
    auto inst = dyn_cast<Instruction>(&*it);
    if ((inst - I) == 0)
      return n;
    n++;
  }
  return n;
}

void JumpTargetManager::registerReadRange(uint64_t Address, uint64_t Size) {
  using interval = boost::icl::interval<uint64_t>;
  ReadIntervalSet += interval::right_open(Address, Address + Size);
}

// TODO: instead of a gigantic switch case we could map the original memory area
//       and write the address of the translated basic block at the jump target
// If this function looks weird it's because it has been designed to be able
// to create the dispatcher in the "root" function or in a standalone function
void JumpTargetManager::createDispatcher(Function *OutputFunction,
                                         Value *SwitchOnPtr) {
  IRBuilder<> Builder(Context);
  QuickMetadata QMD(Context);

  // Create the first block of the dispatcher
  BasicBlock *Entry = BasicBlock::Create(Context,
                                         "dispatcher.entry",
                                         OutputFunction);

  // The default case of the switch statement it's an unhandled cases
  DispatcherFail = BasicBlock::Create(Context,
                                      "dispatcher.default",
                                      OutputFunction);
  Builder.SetInsertPoint(DispatcherFail);

  Module *TheModule = TheFunction->getParent();

  Value *PC = Builder.CreateLoad(pcReg());
  // Value *ELFName = Builder.CreateLoad(elf_name);
  Value *ELFName = dyn_cast<Value>(elf_name);
  auto *UnknownPCTy = FunctionType::get(Type::getVoidTy(Context),
                                        { PC->getType(), ELFName->getType() },
                                        false);
  Constant *UnknownPC = TheModule->getOrInsertFunction("unknownPC",
                                                       UnknownPCTy);
  Builder.CreateCall(cast<Function>(UnknownPC), { PC, ELFName });
  auto *FailUnreachable = Builder.CreateUnreachable();
  FailUnreachable->setMetadata("grin.block.type",
                               QMD.tuple((uint32_t) DispatcherFailureBlock));

  // Switch on the first argument of the function
  Builder.SetInsertPoint(Entry);
  Value *SwitchOn = Builder.CreateLoad(SwitchOnPtr);
  SwitchInst *Switch = Builder.CreateSwitch(SwitchOn, DispatcherFail);
  // The switch is the terminator of the dispatcher basic block
  Switch->setMetadata("grin.block.type", QMD.tuple((uint32_t) DispatcherBlock));

  Dispatcher = Entry;
  DispatcherSwitch = Switch;
  NoReturn.setDispatcher(Dispatcher);

  // Create basic blocks to handle jumps to any PC and to a PC we didn't expect
  AnyPC = BasicBlock::Create(Context, "anypc", OutputFunction);
  UnexpectedPC = BasicBlock::Create(Context, "unexpectedpc", OutputFunction);

  setCFGForm(CFGForm::SemanticPreservingCFG);
}

static void purge(BasicBlock *BB) {
  // Allow up to a single instruction in the basic block
  if (!BB->empty())
    BB->begin()->eraseFromParent();
  grin_assert(BB->empty());
}

std::set<BasicBlock *> JumpTargetManager::computeUnreachable() {
  ReversePostOrderTraversal<BasicBlock *> RPOT(&TheFunction->getEntryBlock());
  std::set<BasicBlock *> Reachable;
  for (BasicBlock *BB : RPOT)
    Reachable.insert(BB);

  // TODO: why is isTranslatedBB(&BB) necessary?
  std::set<BasicBlock *> Unreachable;
  for (BasicBlock &BB : *TheFunction)
    if (Reachable.count(&BB) == 0 and isTranslatedBB(&BB))
      Unreachable.insert(&BB);

  return Unreachable;
}

void JumpTargetManager::setCFGForm(CFGForm::Values NewForm) {
  grin_assert(CurrentCFGForm != NewForm);
  grin_assert(NewForm != CFGForm::UnknownFormCFG);

  std::set<BasicBlock *> Unreachable;

  CFGForm::Values OldForm = CurrentCFGForm;
  CurrentCFGForm = NewForm;

  switch (NewForm) {
  case CFGForm::SemanticPreservingCFG:
    purge(AnyPC);
    BranchInst::Create(dispatcher(), AnyPC);
    // TODO: Here we should have an hard fail, since it's the situation in
    //       which we expected to know where execution could go but we made a
    //       mistake.
    purge(UnexpectedPC);
    BranchInst::Create(dispatcher(), UnexpectedPC);
    break;

  case CFGForm::RecoveredOnlyCFG:
  case CFGForm::NoFunctionCallsCFG:
    purge(AnyPC);
    new UnreachableInst(Context, AnyPC);
    purge(UnexpectedPC);
    new UnreachableInst(Context, UnexpectedPC);
    break;

  default:
    grin_abort("Not implemented yet");
  }

  QuickMetadata QMD(Context);
  AnyPC->getTerminator()->setMetadata("grin.block.type",
                                      QMD.tuple((uint32_t) AnyPCBlock));
  TerminatorInst *UnexpectedPCJump = UnexpectedPC->getTerminator();
  UnexpectedPCJump->setMetadata("grin.block.type",
                                QMD.tuple((uint32_t) UnexpectedPCBlock));

  // If we're entering or leaving the NoFunctionCallsCFG form, update all the
  // branch instruction forming a function call
  if (NewForm == CFGForm::NoFunctionCallsCFG
      || OldForm == CFGForm::NoFunctionCallsCFG) {
    if (auto *FunctionCall = TheModule.getFunction("function_call")) {
      for (User *U : FunctionCall->users()) {
        auto *Call = cast<CallInst>(U);

        // Ignore indirect calls
        // TODO: why this is needed is unclear
        if (isa<ConstantPointerNull>(Call->getArgOperand(0)))
          continue;

        auto *Terminator = cast<TerminatorInst>(nextNonMarker(Call));
        grin_assert(Terminator->getNumSuccessors() == 1);

        // Get the correct argument, the first is the callee, the second the
        // return basic block
        int OperandIndex = NewForm == CFGForm::NoFunctionCallsCFG ? 1 : 0;
        Value *Op = Call->getArgOperand(OperandIndex);
        BasicBlock *NewSuccessor = cast<BlockAddress>(Op)->getBasicBlock();
        Terminator->setSuccessor(0, NewSuccessor);
      }
    }
  }

  rebuildDispatcher();

  if (Verify.isEnabled()) {
    Unreachable = computeUnreachable();
    if (Unreachable.size() != 0) {
      Verify << "The following basic blocks are unreachable after setCFGForm("
             << CFGForm::getName(NewForm) << "):\n";
      for (BasicBlock *BB : Unreachable) {
        Verify << "  " << getName(BB) << " (predecessors:";
        for (BasicBlock *Predecessor : make_range(pred_begin(BB), pred_end(BB)))
          Verify << " " << getName(Predecessor);

        if (uint64_t PC = getBasicBlockPC(BB)) {
          auto It = JumpTargets.find(PC);
          if (It != JumpTargets.end()) {
            Verify << ", reasons:";
            for (const char *Reason : It->second.getReasonNames())
              Verify << " " << Reason;
          }
        }

        Verify << ")\n";
      }
      grin_abort();
    }
  }
}

void JumpTargetManager::rebuildDispatcher() {
  // Remove all cases
  unsigned NumCases = DispatcherSwitch->getNumCases();
  while (NumCases-- > 0)
    DispatcherSwitch->removeCase(DispatcherSwitch->case_begin());

  auto *PCRegType = PCReg->getType()->getPointerElementType();
  auto *SwitchType = cast<IntegerType>(PCRegType);

  // Add all the jump targets if we're using the SemanticPreservingCFG, or
  // only those with no predecessors otherwise
  for (auto &P : JumpTargets) {
    uint64_t PC = P.first;
    BasicBlock *BB = P.second.head();
    if (CurrentCFGForm == CFGForm::SemanticPreservingCFG
        || !hasPredecessors(BB))
      DispatcherSwitch->addCase(ConstantInt::get(SwitchType, PC), BB);
  }

  //
  // Make sure every generated basic block is reachable
  //
  if (CurrentCFGForm != CFGForm::SemanticPreservingCFG) {
    // Compute the set of reachable jump targets
    OnceQueue<BasicBlock *> WorkList;
    for (BasicBlock *BB : DispatcherSwitch->successors())
      WorkList.insert(BB);

    while (not WorkList.empty()) {
      BasicBlock *BB = WorkList.pop();
      for (BasicBlock *Successor : make_range(succ_begin(BB), succ_end(BB)))
        WorkList.insert(Successor);
    }

    std::set<BasicBlock *> Reachable = WorkList.visited();

    // Identify all the unreachable jump targets
    for (auto &P : JumpTargets) {
      uint64_t PC = P.first;
      const JumpTarget &JT = P.second;
      BasicBlock *BB = JT.head();

      // Add to the switch all the unreachable jump targets whose reason is not
      // just direct jump
      if (Reachable.count(BB) == 0
          and not JT.isOnlyReason(JTReason::DirectJump)) {
        DispatcherSwitch->addCase(ConstantInt::get(SwitchType, PC), BB);
      }
    }
  }
}

bool JumpTargetManager::hasPredecessors(BasicBlock *BB) const {
  for (BasicBlock *Pred : predecessors(BB))
    if (isTranslatedBB(Pred))
      return true;
  return false;
}

// Harvesting proceeds trying to avoid to run expensive analyses if not strictly
// necessary, OSRA in particular. To do this we keep in mind two aspects: do we
// have new basic blocks to visit? If so, we avoid any further anyalysis and
// give back control to the translator. If not, we proceed with other analyses
// until we either find a new basic block to translate. If we can't find a new
// block to translate we proceed as long as we are able to create new edges on
// the CFG (not considering the dispatcher).
void JumpTargetManager::harvest() {

  //  if (empty()) {
  //    for (uint64_t PC : SimpleLiterals)
  //      registerJT(PC, JTReason::SimpleLiteral);
  //    SimpleLiterals.clear();
  //  }
  //
  //  if (empty()) {
  //    // Purge all the generated basic blocks without predecessors
  //    std::vector<BasicBlock *> ToDelete;
  //    for (BasicBlock &BB : *TheFunction) {
  //      if (isTranslatedBB(&BB) and &BB != &TheFunction->getEntryBlock()
  //          and pred_begin(&BB) == pred_end(&BB)) {
  //        grin_assert(getBasicBlockPC(&BB) == 0);
  //        ToDelete.push_back(&BB);
  //      }
  //    }
  //    for (BasicBlock *BB : ToDelete)
  //      BB->eraseFromParent();
  //
  //    // TODO: move me to a commit function
  //    // Update the third argument of newpc calls (isJT, i.e., is this
  //    instruction
  //    // a jump target?)
  //    IRBuilder<> Builder(Context);
  //    Function *NewPCFunction = TheModule.getFunction("newpc");
  //    if (NewPCFunction != nullptr) {
  //      for (User *U : NewPCFunction->users()) {
  //        auto *Call = cast<CallInst>(U);
  //        if (Call->getParent() != nullptr) {
  //          // Report the instruction on the coverage CSV
  //          using CI = ConstantInt;
  //          uint64_t PC =
  //          (cast<CI>(Call->getArgOperand(0)))->getLimitedValue();
  //
  //          bool IsJT = isJumpTarget(PC);
  //          Call->setArgOperand(2,
  //          Builder.getInt32(static_cast<uint32_t>(IsJT)));
  //        }
  //      }
  //    }
  //
  //    if (Verify.isEnabled())
  //      grin_assert(not verifyModule(TheModule, &dbgs()));
  //
  //    grin_log(JTCountLog, "Harvesting: SROA, ConstProp, EarlyCSE and SET");
  //
  //    legacy::FunctionPassManager OptimizingPM(&TheModule);
  //    OptimizingPM.add(createSROAPass());
  //    OptimizingPM.add(createConstantPropagationPass());
  //    OptimizingPM.add(createEarlyCSEPass());
  //    OptimizingPM.run(*TheFunction);
  //
  //    legacy::PassManager PreliminaryBranchesPM;
  //    PreliminaryBranchesPM.add(new TranslateDirectBranchesPass(this));
  //    PreliminaryBranchesPM.run(TheModule);
  //
  //    // TODO: eventually, `setCFGForm` should be replaced by using a
  //    CustomCFG
  //    // To improve the quality of our analysis, keep in the CFG only the
  //    edges we
  //    // where able to recover (e.g., no jumps to the dispatcher)
  //    setCFGForm(CFGForm::RecoveredOnlyCFG);
  //
  //    NewBranches = 0;
  //    legacy::PassManager AnalysisPM;
  //    AnalysisPM.add(new SETPass(this, false, &Visited));
  //    AnalysisPM.add(new TranslateDirectBranchesPass(this));
  //    AnalysisPM.run(TheModule);
  //
  //    // Restore the CFG
  //    setCFGForm(CFGForm::SemanticPreservingCFG);
  //
  //    grin_log(JTCountLog,
  //              std::dec << Unexplored.size() << " new jump targets and "
  //                       << NewBranches << " new branches were found");
  //  }

  //  if (not NoOSRA && empty()) {
  //    if (Verify.isEnabled())
  //      grin_assert(not verifyModule(TheModule, &dbgs()));
  //
  //    NoReturn.registerSyscalls(TheFunction);
  //
  //    do {
  //
  //      grin_log(JTCountLog,
  //                "Harvesting: reset Visited, "
  //                  << (NewBranches > 0 ? "SROA, ConstProp, EarlyCSE, " : "")
  //                  << "SET + OSRA");
  //
  //      // TODO: decide what to do with Visited
  //      Visited.clear();
  //      if (NewBranches > 0) {
  //        legacy::FunctionPassManager OptimizingPM(&TheModule);
  //        OptimizingPM.add(createSROAPass());
  //        OptimizingPM.add(createConstantPropagationPass());
  //        OptimizingPM.add(createEarlyCSEPass());
  //        OptimizingPM.run(*TheFunction);
  //      }
  //
  //      legacy::PassManager FunctionCallPM;
  //      FunctionCallPM.add(new FunctionCallIdentification());
  //      FunctionCallPM.run(TheModule);
  //
  //      createJTReasonMD();
  //
  //      setCFGForm(CFGForm::RecoveredOnlyCFG);
  //
  //      NewBranches = 0;
  //      legacy::PassManager AnalysisPM;
  //      AnalysisPM.add(new SETPass(this, true, &Visited));
  //      AnalysisPM.add(new TranslateDirectBranchesPass(this));
  //      AnalysisPM.run(TheModule);
  //
  //      // Restore the CFG
  //      setCFGForm(CFGForm::SemanticPreservingCFG);
  //
  //      grin_log(JTCountLog,
  //                std::dec << Unexplored.size() << " new jump targets and "
  //                         << NewBranches << " new branches were found");
  //
  //    } while (empty() && NewBranches > 0);
  //  }

  // setCFGForm(CFGForm::RecoveredOnlyCFG);

  if (empty()) {
    grin_log(JTCountLog, "We're done looking for jump targets");
  }
}

void JumpTargetManager::pushpartCFGStack(llvm::BasicBlock *dest,
                                         uint64_t DAddr,
                                         llvm::BasicBlock *src,
                                         uint64_t SAddr) {
  partCFG.push_back(std::make_tuple(dest, DAddr, src, SAddr));
  std::get<0>(nodepCFG) = dest;
  std::get<1>(nodepCFG) = src;
}

void JumpTargetManager::searchpartCFG(
  std::map<llvm::BasicBlock *, llvm::BasicBlock *> &DONE) {
  // Match source BB, to search start entry of one path.
  llvm::Function::iterator it(std::get<1>(nodepCFG));
  llvm::Function::iterator begin(it->getParent()->begin());

  for (; it != begin; it--) {
    auto bb = dyn_cast<llvm::BasicBlock>(it);
    for (auto p : partCFG) {
      if ((bb - std::get<0>(p)) == 0) {
        if (DONE.find(bb) != DONE.end())
          break;
        std::get<0>(nodepCFG) = std::get<0>(p);
        std::get<1>(nodepCFG) = std::get<2>(p);
        DONE[std::get<0>(p)] = std::get<2>(p);
        return;
      }
    }
  }
  std::get<0>(nodepCFG) = nullptr;
  std::get<1>(nodepCFG) = nullptr;
}

uint32_t JumpTargetManager::belongToUBlock(llvm::BasicBlock *block) {
  llvm::StringRef str = block->getName();
  LLVM_NODISCARD size_t nPos1 = llvm::StringRef::npos;
  LLVM_NODISCARD size_t nPos2 = llvm::StringRef::npos;
  llvm::StringRef substr = "";
  nPos1 = str.find_last_of(".");
  nPos2 = str.find_last_of(".", nPos1 - 1);
  if (nPos1 > nPos2) {
    substr = str.substr(nPos2 + 1, nPos1 - nPos2 - 1);
  } else {
    substr = str.substr(nPos1 + 1, str.size() - nPos1 - 1);
  }

  // TODO: Get user defined code range.
  llvm::StringRef UserCodeName = "main";
  if (substr.equals(UserCodeName))
    return 1;

  return 0;
}

bool JumpTargetManager::isDataSegmAddr(uint64_t PC) {
  return ptc.is_image_addr(PC);
}

bool JumpTargetManager::isELFDataSegmAddr(uint64_t PC) {
  bool flag = false;
  if (ro_StartAddr <= PC and PC < ro_EndAddr)
    flag = true;
  return (ptc.is_image_addr(PC) or flag);
}

std::pair<bool, uint32_t> JumpTargetManager::islegalAddr(llvm::Value *v) {
  uint64_t va = 0;
  StringRef Iargs = v->getName();
  uint32_t registerName = 0;

  auto op = StrToInt(Iargs.data());
  // errs()<<op<<"+++\n";
  switch (op) {
  case RAX:
    va = ptc.regs[R_EAX];
    registerName = RAX;
    errs() << va << " :eax\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RAX);
    break;
  case RCX:
    va = ptc.regs[R_ECX];
    registerName = RCX;
    // errs()<<ptc.regs[R_ECX]<<" ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RCX);
    break;
  case RDX:
    va = ptc.regs[R_EDX];
    registerName = RDX;
    errs() << ptc.regs[R_EDX] << " ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RDX);
    break;
  case RBX:
    va = ptc.regs[R_EBX];
    registerName = RBX;
    // errs()<<ptc.regs[R_EBX]<<" ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RBX);
    break;
  case RSP:
    va = ptc.regs[R_ESP];
    registerName = RSP;
    // errs()<<ptc.regs[R_ESP]<<" ++\n";
    if (!isDataSegmAddr(va)) {
      errs() << "RSP shouldn't be illegal address!\n";
      return std::make_pair(0, RSP);
    }
    break;
  case RBP:
    va = ptc.regs[R_EBP];
    registerName = RBP;
    errs() << ptc.regs[R_EBP] << " ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RBP);
    break;
  case RSI:
    va = ptc.regs[R_ESI];
    registerName = RSI;
    // errs()<<ptc.regs[R_ESI]<<" ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RSI);
    break;
  case RDI:
    va = ptc.regs[R_EDI];
    registerName = RDI;
    errs() << ptc.regs[R_EDI] << " ++\n";
    if (!isDataSegmAddr(va))
      return std::make_pair(0, RDI);
    break;
  case R8:
    va = ptc.regs[R_8];
    registerName = R8;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R8);
    break;
  case R9:
    va = ptc.regs[R_9];
    registerName = R9;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R9);
    break;
  case R10:
    va = ptc.regs[R_10];
    registerName = R10;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R10);
    break;
  case R11:
    va = ptc.regs[R_11];
    registerName = R11;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R11);
    break;
  case R12:
    va = ptc.regs[R_12];
    registerName = R12;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R12);
    break;
  case R13:
    va = ptc.regs[R_13];
    registerName = R13;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R13);
    break;
  case R14:
    va = ptc.regs[R_14];
    registerName = R14;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R14);
    break;
  case R15:
    va = ptc.regs[R_15];
    registerName = R15;
    if (!isDataSegmAddr(va))
      return std::make_pair(0, R15);
    break;
  default:
    errs() << "No match register arguments! \n";
  }
  return std::make_pair(1, registerName);
}

JumpTargetManager::LastAssignmentResultWithInst
JumpTargetManager::getLastAssignment(llvm::Value *v,
                                     llvm::User *userInst,
                                     llvm::BasicBlock *currentBB,
                                     TrackbackMode TrackType,
                                     uint32_t &NUMOFCONST) {
  if (dyn_cast<ConstantInt>(v)) {
    return std::make_pair(ConstantValueAssign, nullptr);
  }
  switch (TrackType) {
  case FullMode:
  case CrashMode: {
    if (v->getName().equals("rsp"))
      return std::make_pair(ConstantValueAssign, nullptr);
  } break;
  case InterprocessMode: {
    if (v->getName().equals("rsp")) {
      NUMOFCONST--;
      if (NUMOFCONST == 0)
        return std::make_pair(ConstantValueAssign, nullptr);
    }

  } break;
  case TestMode: {
    if (v->getName().equals("rsp")) {
      NUMOFCONST--;
      if (NUMOFCONST == 0)
        return std::make_pair(ConstantValueAssign, nullptr);
    }
  }
  case JumpTableMode: {
    auto op = StrToInt(v->getName().data());
    switch (op) {
    case RAX:
    case RBX:
    case RCX:
    case RDX:
    case RSI:
    case RDI:
    case RSP:
    case RBP:
    case R8:
    case R9:
    case R10:
    case R11:
    case R12:
    case R13:
    case R14:
    case R15: {
      if (NUMOFCONST == 0)
        return std::make_pair(ConstantValueAssign, nullptr);
      NUMOFCONST--;
    } break;
    }
  } break;
  case RangeMode: {
    auto op = StrToInt(v->getName().data());
    switch (op) {
    case RAX:
    case RBX:
    case RCX:
    case RDX:
    case RSI:
    case RDI:
    case RSP:
    case R8:
    case R9:
    case R10:
    case R11:
    case R12:
    case R13:
    case R14:
    case R15: {
      return std::make_pair(ConstantValueAssign, nullptr);
    } break;
    }
  } break;
  }

  errs() << currentBB->getName()
         << "               **************************************\n\n ";
  bool bar = 0;
  std::vector<llvm::Instruction *> vDefUse;
  for (User *vu : v->users()) {
    // errs()<<*vu<<"\n";
    if ((vu - userInst) == 0)
      bar = 1;
    auto *vui = dyn_cast<Instruction>(vu);
    if (bar && ((vui->getParent() - currentBB) == 0)) {
      // errs()<<*vu<<" userInst****\n";
      vDefUse.push_back(vui);
    }
    /*
    if(bar && ((vui->getParent() - thisBlock) != 0))
      break;
    */
  }
  if (vDefUse.empty()) {
    bar = 0;
    std::vector<Instruction *> UserOFbv;
    for (auto &Ib : make_range(currentBB->begin(), currentBB->end())) {
      for (auto &Ub : Ib.operands()) {
        Value *Vb = Ub.get();
        if ((v - Vb) == 0) {
          UserOFbv.push_back(dyn_cast<Instruction>(&Ib));
          break;
        }
      }
    }
    for (auto vuInst : make_range(UserOFbv.rbegin(), UserOFbv.rend())) {
      if ((dyn_cast<User>(vuInst) - userInst) == 0)
        bar = 1;
      if (bar)
        vDefUse.push_back(vuInst);
    }

    if (vDefUse.empty())
      vDefUse = UserOFbv;
  }

  auto def = dyn_cast<Instruction>(v);
  //  if(vDefUse.size() == 1){
  //        //vDefUse[0]->getOpcode() == llvm::Instruction::Store
  //        if(def){
  //          errs()<<*def<<"return def instruction\n";
  //          return CurrentBlockValueDef;
  //        }
  //        else{
  //          errs()<<" explort next BasicBlock! return v\n";
  //          return NextBlockOperating;
  //        }
  //  }
  if (vDefUse.size() >= 1) {
    for (auto last : vDefUse) {
      /* As user, only store is assigned to Value */
      switch (last->getOpcode()) {
      case llvm::Instruction::Store: {
        auto lastS = dyn_cast<llvm::StoreInst>(last);
        if ((lastS->getPointerOperand() - v) == 0) {
          errs() << *last << "\n^--last assignment\n";
          return std::make_pair(CurrentBlockLastAssign, last);
        }
        break;
      }
      case llvm::Instruction::Load:
      case llvm::Instruction::Select:
      case llvm::Instruction::ICmp:
      case llvm::Instruction::IntToPtr:
      case llvm::Instruction::Add:
      case llvm::Instruction::Sub:
      case llvm::Instruction::And:
      case llvm::Instruction::ZExt:
      case llvm::Instruction::SExt:
      case llvm::Instruction::Trunc:
      case llvm::Instruction::Shl:
      case llvm::Instruction::LShr:
      case llvm::Instruction::AShr:
      case llvm::Instruction::Or:
      case llvm::Instruction::Xor:
      case llvm::Instruction::Br:
      case llvm::Instruction::Call:
      case llvm::Instruction::Mul:
        continue;
        break;
      default:
        errs() << "Unkonw instruction: " << *last << "\n";
        grin_abort("Unkonw instruction!");
        break;
      }
    }
    if (def) {
      errs() << *def << "\n^--many or one user, return def instruction\n";
      return std::make_pair(CurrentBlockValueDef, def);
    } else {
      errs() << "--no assignment, to explort next BasicBlock of Value's "
                "users\n";
      return std::make_pair(NextBlockOperating, nullptr);
    }
  }

  return std::make_pair(UnknowResult, nullptr);
}

void JumpTargetManager::harvestBlockPCs(std::vector<uint64_t> &BlockPCs) {
  if (BlockPCs.empty())
    return;
  int i = 0;
  for (auto pc : BlockPCs) {
    if (!haveTranslatedPC(pc, 0) && !isIllegalStaticAddr(pc))
      StaticAddrs[pc] = false;
    i++;
    if (i >= 3)
      break;
  }
}

void JumpTargetManager::harvestVirtualTableAddr(llvm::BasicBlock *thisBlock,
                                                uint64_t base) {
  for (size_t n = 0;; n++) {
    uint64_t addr = (uint64_t)(base + (n << 3));
    addr = *((uint64_t *) addr);
    if (addr == 0)
      continue;
    if (isExecutableAddress(addr)) {
      auto thisAddr = getInstructionPC(&*(thisBlock->begin()));
      harvestBTBasicBlock(thisBlock, thisAddr, addr);
    } else
      break;
  }
}

void JumpTargetManager::handleLibCalling(uint64_t &DynamicVirtualAddress) {
  if (DynamicVirtualAddress == 0)
    return;

  if (!isExecutableAddress(DynamicVirtualAddress)) {
    DynamicVirtualAddress = ptc.run_library(2);
    return;
  }
}

void JumpTargetManager::handleInvalidAddr(uint64_t &DynamicVirtualAddress) {
  // handle invalid address
  if (!isExecutableAddress(DynamicVirtualAddress)) {
    DynamicVirtualAddress = 0;
    return;
  }
  if (*ptc.isRet) {
    std::set<uint64_t>::iterator Target = BranchAddrs.find(
      DynamicVirtualAddress);
    if (Target == BranchAddrs.end())
      DynamicVirtualAddress = 0;
  }
}

void JumpTargetManager::generatePartCFGWithNext(uint64_t src,
                                                uint64_t dest,
                                                llvm::BasicBlock *thisBlock) {
  if (thisBlock == nullptr)
    return;
  BasicBlock::iterator I = --(thisBlock->end());
  if (auto branch = dyn_cast<BranchInst>(I)) {
    if (branch->isUnconditional()) {
      auto nextB = dyn_cast<BasicBlock>(branch->getOperand(0));
      dest = getInstructionPC(&*nextB->begin());
      // outs()<<*I<<"\n";
    }
  }

  SrcToDestsMap::iterator Target = SrcToDestsWithNext.find(src);
  if (Target != SrcToDestsWithNext.end()) {
    Target->second.insert(dest);
    return;
  }
  std::set<uint64_t> tmp;
  tmp.insert(dest);
  SrcToDestsWithNext[src] = tmp;
}
void JumpTargetManager::generatePartCFG(uint64_t src,
                                        uint64_t dest,
                                        llvm::BasicBlock *thisBlock) {
  if (thisBlock == nullptr)
    return;
  BasicBlock::iterator I = --(thisBlock->end());
  if (auto branch = dyn_cast<BranchInst>(I)) {
    if (branch->isUnconditional()) {
      auto nextB = dyn_cast<BasicBlock>(branch->getOperand(0));
      dest = getInstructionPC(&*nextB->begin());
      // outs()<<*I<<"\n";
    }
  }

  SrcToDestsMap::iterator Target = SrcToDests.find(src);
  if (Target != SrcToDests.end()) {
    Target->second.insert(dest);
    return;
  }
  std::set<uint64_t> tmp;
  tmp.insert(dest);
  SrcToDests[src] = tmp;
}

void JumpTargetManager::registerJumpTable(llvm::BasicBlock *thisBlock,
                                          llvm::Instruction *shl,
                                          llvm::Instruction *add,
                                          uint64_t thisAddr,
                                          int64_t base,
                                          int64_t offset) {
  auto Path = outputpath + ".JumpTable.log";
  std::ofstream JTAddr;
  JTAddr.open(Path, std::ofstream::out | std::ofstream::app);
  JTAddr << "0x" << std::hex << thisAddr << "\n";

  if (isExecutableAddress((uint64_t) base)) {
    JTAddr.close();
    return;
  }
  if (!isELFDataSegmAddr((uint64_t) base)) {
    JTAddr.close();
    return;
  }
  JumpTableBase[base] = offset;

  // Get index
  uint32_t index = UndefineOP;
  BasicBlock::reverse_iterator I(shl);
  BasicBlock::reverse_iterator rend(thisBlock->rend());
  for (; I != rend; I++) {
    if (I->getOpcode() == Instruction::Load) {
      auto load = dyn_cast<LoadInst>(&*I);
      auto v = load->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        auto str = v->getName();
        index = REGLABLE(StrToInt(str.data()));
        if (index == UndefineOP)
          grin_abort("Unkown register OP!\n");
        break;
      }
    }
  }
  // Get start PC
  auto start = getInstructionPC(shl);
  grin_assert(start);

  // Running gadgets
  bool recover = false;
  std::set<uint64_t> JTtargets;
  if (ptc.is_stack_addr(ptc.regs[R_ESP])) {
    ptc.storeStack();
    recover = true;
  }
  storeCPURegister();
  for (int i = 0; i < 2000; i++) {
    ptc.regs[index] = i;
    int64_t addr = ptc.exec(start);
    auto tmp = getStaticAddrfromDestRegs(add, thisAddr);
    if (tmp == 1) {
      if (*ptc.isIndirect or *ptc.isIndirectJmp) {
        if (isExecutableAddress(addr)) {
          JTAddr << "---------> " << std::hex << addr << "\n";
          JTtargets.insert(addr);
          continue;
        }
      }
      break;
    } else {
      if (tmp == 0)
        continue;
      JTAddr << "---------> " << std::hex << tmp << "\n";
      JTtargets.insert(tmp);
    }
  }
  recoverCPURegister();
  if (recover)
    ptc.recoverStack();

  if (!JTtargets.empty()) {
    std::set<uint64_t>::iterator it = JTtargets.begin();
    for (; it != JTtargets.end(); it++)
      harvestBTBasicBlock(thisBlock, thisAddr, *it);
  }
  JTAddr.close();
}

void JumpTargetManager::harvestJumpTableAddr(llvm::BasicBlock *thisBlock,
                                             uint64_t thisAddr) {
  BasicBlock::iterator begin(thisBlock->begin());
  BasicBlock::iterator end(thisBlock->end());

  auto I = begin;
  uint32_t isJumpTable = 0;
  llvm::Instruction *shl = nullptr;
  llvm::Instruction *shlIt = nullptr;
  llvm::Instruction *add = nullptr;
  int64_t base = 0;
  int64_t offset = 0;

  for (; I != end; I++) {
    auto op = I->getOpcode();
    if (op == Instruction::Call) {
      auto call = dyn_cast<CallInst>(&*I);
      auto callee = call->getCalledFunction();
      if (callee != nullptr and callee->getName() == "newpc") {
        isJumpTable = 0;
        shl = nullptr;
        if (offset) {
          registerJumpTable(thisBlock, shlIt, add, thisAddr, base, offset);
          offset = 0;
          base = 0;
        }
      }
    }
    if (op == Instruction::Shl) {
      isJumpTable = 0;
      isJumpTable++;
      shl = dyn_cast<llvm::Instruction>(I);
    }

    if (op == Instruction::Add) {
      isJumpTable = isJumpTable + 2;
      if (isJumpTable == 3 or isJumpTable == 5) {
        if (shl) {
          offset = GetConst(shl, shl->getOperand(1));
          shlIt = shl;
          shl = nullptr;
        }
        add = dyn_cast<llvm::Instruction>(I);
        base = base + GetConst(add, add->getOperand(1));
      }
    }
  }

  if (offset)
    registerJumpTable(thisBlock, shlIt, add, thisAddr, base, offset);
}

int64_t JumpTargetManager::GetConst(llvm::Instruction *I, llvm::Value *v) {
  auto Path = outputpath + ".JumpTable.log";
  std::ofstream JTAddr;
  JTAddr.open(Path, std::ofstream::out | std::ofstream::app);

  BasicBlock::reverse_iterator it(I);
  BasicBlock::reverse_iterator rend = I->getParent()->rend();

  if (dyn_cast<Constant>(v)) {
    if (dyn_cast<ConstantInt>(v)) {
      auto integer = llvm::cast<llvm::ConstantInt>(v)->getSExtValue();
      JTAddr << integer << "\n";
      JTAddr.close();
      return integer;
    } else {
      auto str = v->getName();
      JTAddr << str.str();
      auto lable = REGLABLE(StrToInt(str.data()));
      if (lable == UndefineOP)
        return 0;
      JTAddr << " : " << std::hex << ptc.regs[lable] << "\n";
      JTAddr.close();
      return ptc.regs[lable];
    }
  }

  it++;
  for (; it != rend; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        return 0;
      break;
    }
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(&*it);
      if ((dyn_cast<Value>(load) - v) == 0) {
        v = load->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          if (dyn_cast<ConstantInt>(v)) {
            auto integer = llvm::cast<llvm::ConstantInt>(v)->getSExtValue();
            JTAddr << integer << "\n";
            JTAddr.close();
            return integer;
          } else {
            auto str = v->getName();
            JTAddr << str.str();
            auto lable = REGLABLE(StrToInt(str.data()));
            JTAddr << " : " << std::hex << ptc.regs[lable] << "\n";
            JTAddr.close();
            if (lable == UndefineOP)
              return 0;

            return ptc.regs[lable];
          }
        }
      }
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(&*it);
      if ((store->getPointerOperand() - v) == 0) {
        v = store->getValueOperand();
        if (dyn_cast<Constant>(v)) {
          if (dyn_cast<ConstantInt>(v)) {
            auto integer = llvm::cast<llvm::ConstantInt>(v)->getSExtValue();
            JTAddr << integer << "\n";
            JTAddr.close();
            return integer;
          } else {
            auto str = v->getName();
            JTAddr << str.str();
            auto lable = REGLABLE(StrToInt(str.data()));
            if (lable == UndefineOP)
              return 0;
            JTAddr << " : " << std::hex << ptc.regs[lable] << "\n";
            JTAddr.close();
            return ptc.regs[lable];
          }
        }
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(&*it);
      if ((v - dyn_cast<Value>(instr)) == 0) {
        auto num = instr->getNumOperands();
        if (num > 1)
          return 0;
        for (Use &u : instr->operands()) {
          Value *InstV = u.get();
          v = InstV;
        }
      }
      break;
    }
    }
  } //??end for

  return 0;
}

void JumpTargetManager::storeCPURegister() {
  TempCPURegister.clear();
  for (int i = 0; i < REGS; i++)
    TempCPURegister.push_back(ptc.regs[i]);
}
void JumpTargetManager::cleanCPURegister() {
  for (int i = 0; i < REGS; i++) {
    if (i == R_ESP)
      continue;
    ptc.regs[i] = 0;
  }
}
void JumpTargetManager::recoverCPURegister() {
  for (size_t i = 0; i < TempCPURegister.size(); i++)
    ptc.regs[i] = TempCPURegister[i];
}

void JumpTargetManager::getGloFromTempReg(
  llvm::Instruction *I,
  std::map<uint32_t, uint64_t> &GloData) {
  BasicBlock::iterator begin = I->getParent()->begin();
  BasicBlock::iterator end = I->getParent()->end();

  uint64_t begin_addr = getInstructionPC(&*I->getParent()->begin());
  uint64_t end_addr = getInstructionPC(I);

  // Store program states.
  // Clean states.
  bool recover = false;
  int32_t tmp_syscall = *ptc.exception_syscall;
  if (ptc.is_stack_addr(ptc.regs[R_ESP])) {
    ptc.storeStack();
    recover = true;
  }
  storeCPURegister();
  ptc.mmap(0, 0x1000);

  // run it
  ptc.exec1(begin_addr, end_addr);

  // Obtain global data from temp reg.
  auto it = begin;
  it++;
  for (; it != end; it++) {
    if (it->getOpcode() == Instruction::Call) {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc") {
        auto addr = getLimitedValue(callI->getArgOperand(0));
        if (addr == end_addr)
          break;
      }
    }
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(it);
      auto v = store->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        auto op = getOP(v);
        if (op == UndefineOP)
          continue;
        if (op != UndefineOP and isGlobalData(ptc.regs[op]))
          GloData[op] = ptc.regs[op];
      }
    }
  }

  // Restore program states.
  ptc.unmmap(0, 0x1000);
  recoverCPURegister();
  *ptc.exception_syscall = tmp_syscall;
  if (recover)
    ptc.recoverStack();
}

void JumpTargetManager::harvestCodePointerInDataSegment(int64_t pos) {
  std::vector<int64_t> GadgeChain;
  GadgeChain.push_back(pos);
  int64_t pos_base = pos;
  while (assign_gadge[pos_base].second.pre != -1) {
    pos_base = assign_gadge[pos_base].second.pre;
    GadgeChain.push_back(pos_base);
  }
  std::set<uint64_t> tmpGlobal;
  std::set<uint64_t> &tmpGlobal1 = tmpGlobal;
  std::vector<int64_t>::reverse_iterator rit = GadgeChain.rbegin();
  tmpGlobal1.insert(assign_gadge[*rit].first);

  // Store program states.
  // Clean states.
  bool recover = false;
  int32_t tmp_syscall = *ptc.exception_syscall;
  if (ptc.is_stack_addr(ptc.regs[R_ESP])) {
    ptc.storeStack();
    recover = true;
  }
  storeCPURegister();
  cleanCPURegister();
  ptc.mmap(0, 0x1000);

  for (; rit != GadgeChain.rend(); rit++) {
    auto gadget = assign_gadge[*rit].second.static_addr_block;
    bool oper = false;
    if (assign_gadge[*rit].second.operation_block) {
      gadget = assign_gadge[*rit].second.operation_block;
      oper = true;
    }
    auto global_I = assign_gadge[*rit].second.global_I;
    auto op = assign_gadge[*rit].second.op;
    auto indirect = assign_gadge[*rit].second.indirect;
    auto isloop = assign_gadge[*rit].second.isloop;
    runGlobalGadget(gadget, oper, global_I, op, indirect, isloop, tmpGlobal1);
  }

  // Restore program states.
  ptc.unmmap(0, 0x1000);
  recoverCPURegister();
  *ptc.exception_syscall = tmp_syscall;
  if (recover)
    ptc.recoverStack();


  AllGloCandidataAddr.clear();
}

void JumpTargetManager::DirectCodePointerHarvest(int64_t pos) {
  std::set<uint64_t> tmpGlobal;
  std::set<uint64_t> &tmpGlobal1 = tmpGlobal;

  tmpGlobal1.insert(assign_gadge[pos].first);
  auto gadget = assign_gadge[pos].second.static_addr_block;
  auto global_I = assign_gadge[pos].second.global_I;
  auto op = assign_gadge[pos].second.op;
  auto indirect = assign_gadge[pos].second.indirect;

  // Store program states.
  // Clean states.
  bool recover = false;
  int32_t tmp_syscall = *ptc.exception_syscall;
  if (ptc.is_stack_addr(ptc.regs[R_ESP])) {
    ptc.storeStack();
    recover = true;
  }
  storeCPURegister();
  cleanCPURegister();
  ptc.mmap(0, 0x1000);

  runGlobalGadget(gadget, false, global_I, op, indirect, 1, tmpGlobal1);

  ptc.unmmap(0, 0x1000);
  recoverCPURegister();
  *ptc.exception_syscall = tmp_syscall;
  if (recover)
    ptc.recoverStack();


  AllGloCandidataAddr.clear();
}

void JumpTargetManager::scanMemoryBlock(uint64_t start,
                                        uint64_t end,
                                        llvm::BasicBlock *thisBlock,
                                        uint64_t thisAddr) {
  if (isRecordCandidataAddr)
    return;

  if (start > end)
    return;
  auto base = start;

  /* we only scan half a memory block page  */
  // uint64_t PAGE = 1<<11;
  // if((end-start)>PAGE)
  //  end = start + PAGE;

  while (base < end) {
    if (!isGlobalData(base))
      break;
    auto pc = *((uint64_t *) base);
    if (isExecutableAddress(pc))
      harvestBTBasicBlock(thisBlock, thisAddr, pc);
    base = base + 0x8;
  }
}

void JumpTargetManager::runGlobalGadget(llvm::BasicBlock *gadget,
                                        bool oper,
                                        llvm::Instruction *global_I,
                                        uint32_t op,
                                        bool indirect,
                                        uint32_t isloop,
                                        std::set<uint64_t> &tmpGlobal) {
  if (gadget == nullptr or global_I == nullptr)
    return;
  auto thisAddr = getInstructionPC(&*(gadget->begin()));
  if (thisAddr == 0)
    return;
  auto current_pc = getInstructionPC(global_I);
  std::set<uint64_t> tempVec;
  std::set<uint64_t> &tempVec1 = tempVec;
  std::set<uint64_t> JTtargets;
  std::set<uint64_t> &JTtargets1 = JTtargets;
  uint64_t tmpGlobalFirst = 0;

  if (tmpGlobal.empty())
    return;

  uint32_t opt = UndefineOP;
  uint64_t virtualAddr = 0;
  if (current_pc != thisAddr) {
    std::tie(opt, virtualAddr) = getLastOperandandNextPC(&*(gadget->begin()),
                                                         global_I);
    if (virtualAddr == 0)
      return;
  }
  if (current_pc == thisAddr) {
    opt = getOffsetReg(global_I);
    // Handle *(base+index)+offset.
    // Get reg of the offset.
    // e.g., add 0x8724e0(%rbp), %rbx ;rbx is offset reg.
    if (isloop and opt == UndefineOP) {
      auto OPs = getIndexReg(global_I);
      if (!OPs.empty())
        opt = OPs.back();
    }
    if (opt != UndefineOP) {
      virtualAddr = current_pc;
      thisAddr = 0;
    }
  }

  /* If the instruction to operate global data is entry address,
   * we consider that no instruction operates offset, and offset value
   * has been designated in global_I. */
  if (current_pc == thisAddr or opt == UndefineOP) {
    for (auto base : tmpGlobal) {
      if (op != UndefineOP)
        ptc.regs[op] = base;
      ConstOffsetExec(gadget,
                      thisAddr,
                      current_pc,
                      oper,
                      global_I,
                      op,
                      indirect,
                      isloop,
                      tempVec1,
                      JTtargets1);
    }
    tmpGlobalFirst = *(tmpGlobal.begin());
    tmpGlobal.clear();
    tmpGlobal = tempVec1;

    if (!JTtargets1.empty()) {
      auto Path = outputpath + ".StaticAddrs.csv";
      std::ofstream SAs;
      SAs.open(Path, std::ofstream::out | std::ofstream::app);

      std::set<uint64_t>::iterator it = JTtargets1.begin();
      for (; it != JTtargets1.end(); it++) {
        harvestBTBasicBlock(gadget, thisAddr, *it);
        if (isRecordCandidataAddr)
          SAs << std::hex << *it << "\n";
      }
      if (isROData(tmpGlobalFirst) and !isRecordCandidataAddr) {
        scanMemoryBlock(tmpGlobalFirst, BlockBound, gadget, thisAddr);
        BlockBound = 0;
      }
      SAs.close();
    }
    return;
  }

  /* If the instruction to operate global data isn't entry address of block,
   * then we consider all instructions before this instruction will be the
   * instruction to operate offset value. */
  if (thisAddr == 0)
    thisAddr = current_pc;
  for (auto base : tmpGlobal) {
    if (op != UndefineOP)
      ptc.regs[op] = base;
    VarOffsetExec(gadget,
                  thisAddr,
                  virtualAddr,
                  current_pc,
                  oper,
                  global_I,
                  op,
                  opt,
                  indirect,
                  isloop,
                  tempVec1,
                  JTtargets1);
  }
  tmpGlobalFirst = *(tmpGlobal.begin());
  tmpGlobal.clear();
  tmpGlobal = tempVec1;

  if (!JTtargets1.empty()) {
    auto Path = outputpath + ".StaticAddrs.csv";
    std::ofstream SAs;
    SAs.open(Path, std::ofstream::out | std::ofstream::app);

    std::set<uint64_t>::iterator it = JTtargets1.begin();
    for (; it != JTtargets1.end(); it++) {
      harvestBTBasicBlock(gadget, thisAddr, *it);
      if (isRecordCandidataAddr)
        SAs << std::hex << *it << "\n";
    }
    if (isROData(tmpGlobalFirst) and !isRecordCandidataAddr) {
      scanMemoryBlock(tmpGlobalFirst, BlockBound, gadget, thisAddr);
      BlockBound = 0;
    }
    SAs.close();
  }
}

void JumpTargetManager::ConstOffsetExec(llvm::BasicBlock *gadget,
                                        uint64_t thisAddr,
                                        uint64_t current_pc,
                                        bool oper,
                                        llvm::Instruction *global_I,
                                        uint32_t op,
                                        bool indirect,
                                        uint32_t isloop,
                                        std::set<uint64_t> &tempVec,
                                        std::set<uint64_t> &JTtargets) {
  size_t pagesize = 0;

  
  for (;;) {
    // Static addresses are indirect jump target address.
    int64_t tmpPC = ptc.exec(thisAddr);

    if (oper) {
      auto data = getGlobalDatafromDestRegs(global_I);
      if (!isGlobalData(data))
        break;
      auto it = tempVec.find(data);
      if (it == tempVec.end()) {
        tempVec.insert(data);
      }
      // if(isRecordCandidataAddr){
      std::map<uint64_t, uint32_t>::iterator Target1 = AllGloCandidataAddr.find(
        data - 1);
      std::map<uint64_t, uint32_t>::iterator Target2 = AllGloCandidataAddr.find(
        data - 2);
      std::map<uint64_t, uint32_t>::iterator Target3 = AllGloCandidataAddr.find(
        data - 3);
      std::map<uint64_t, uint32_t>::iterator Target4 = AllGloCandidataAddr.find(
        data - 4);
      if (Target1 != AllGloCandidataAddr.end()
          or Target2 != AllGloCandidataAddr.end()
          or Target3 != AllGloCandidataAddr.end()
          or Target4 != AllGloCandidataAddr.end())
        break;
      AllGloCandidataAddr[data] = 1;
      // }
      pagesize++;
      if (!isRecordCandidataAddr and pagesize > DCPH)
        break;
      if (isRecordCandidataAddr and pagesize > LoopNums)
        break;
      // handle lea during executing loop gadget
      if (isloop == 2)
        ptc.regs[op] = data;
      if (!isloop)
        break;
      continue;
    }
    std::pair<uint64_t, uint32_t> entryinfo{ 0, UndefineOP };
    // Static addresses stored in registers.
    if (!indirect)
      tmpPC = getStaticAddrfromDestRegs(global_I, current_pc, entryinfo);
    pagesize++;
    if (!isRecordCandidataAddr and pagesize > DCPH)
      break;
    if (isRecordCandidataAddr and pagesize > LoopNums)
      break;
    if (isExecutableAddress(tmpPC)) {
      auto targetIT = JTtargets.find(tmpPC);
      if (targetIT == JTtargets.end()) {
        JTtargets.insert(tmpPC);
        if (CFG) {
          auto InfoPath = outputpath + ".EntryInfo.csv";
          std::ofstream Info;
          Info.open(InfoPath, std::ofstream::out | std::ofstream::app);
          // SrcAddr, AddrOfReg, reg, entry
          Info << std::hex << thisAddr << " ";
          Info << std::hex << entryinfo.first << " ";
          Info << entryinfo.second << " ";
          Info << std::hex << tmpPC << "\n";
        }
        // harvestBTBasicBlock(gadget,thisAddr,tmpPC);
        
        if (op != UndefineOP)
          BlockBound = ptc.regs[op];
      }
    }
    if (!isloop)
      break;
  }
}

void JumpTargetManager::VarOffsetExec(llvm::BasicBlock *gadget,
                                      uint64_t thisAddr,
                                      uint64_t virtualAddr,
                                      uint64_t current_pc,
                                      bool oper,
                                      llvm::Instruction *global_I,
                                      uint32_t op,
                                      uint32_t opt,
                                      bool indirect,
                                      uint32_t isloop,
                                      std::set<uint64_t> &tempVec,
                                      std::set<uint64_t> &JTtargets) {
  size_t pagesize = 0;

  for (int i = 0;; i++) {
    if (isloop and thisAddr == current_pc)
      ptc.regs[opt] = i * 8;
    else
      ptc.regs[opt] = i;
    // Static addresses are indirect jump target address.
    int64_t tmpPC = ptc.exec(virtualAddr);

    if (oper) {
      // TODO:vector data ?
      auto data = getGlobalDatafromDestRegs(global_I);
      if (!isGlobalData(data))
        break;
      auto it = tempVec.find(data);
      if (it == tempVec.end()) {
        tempVec.insert(data);
      }
      // if(isRecordCandidataAddr){
      std::map<uint64_t, uint32_t>::iterator Target1 = AllGloCandidataAddr.find(
        data - 1);
      std::map<uint64_t, uint32_t>::iterator Target2 = AllGloCandidataAddr.find(
        data - 2);
      std::map<uint64_t, uint32_t>::iterator Target3 = AllGloCandidataAddr.find(
        data - 3);
      std::map<uint64_t, uint32_t>::iterator Target4 = AllGloCandidataAddr.find(
        data - 4);
      if (Target1 != AllGloCandidataAddr.end()
          or Target2 != AllGloCandidataAddr.end()
          or Target3 != AllGloCandidataAddr.end()
          or Target4 != AllGloCandidataAddr.end())
        break;
      AllGloCandidataAddr[data] = 1;
      //}
      pagesize++;
      if (!isRecordCandidataAddr and pagesize > DCPH)
        break;
      if (isRecordCandidataAddr and pagesize > LoopNums)
        break;
      if (!isloop)
        break;
      continue;
    }
    std::pair<uint64_t, uint32_t> entryinfo{ 0, UndefineOP };
    // Static addresses stored in registers.
    if (!indirect)
      tmpPC = getStaticAddrfromDestRegs(global_I, current_pc, entryinfo);
    pagesize++;
    if (!isRecordCandidataAddr and pagesize > DCPH)
      break;
    if (isRecordCandidataAddr and pagesize > LoopNums)
      break;
    if (isExecutableAddress(tmpPC)) {
      auto targetIT = JTtargets.find(tmpPC);
      if (targetIT == JTtargets.end()) {
        JTtargets.insert(tmpPC);
        if (CFG) {
          auto InfoPath = outputpath + ".EntryInfo.csv";
          std::ofstream Info;
          Info.open(InfoPath, std::ofstream::out | std::ofstream::app);
          // SrcAddr, AddrOfReg, reg, entry
          Info << std::hex << thisAddr << " ";
          Info << std::hex << entryinfo.first << " ";
          Info << entryinfo.second << " ";
          Info << std::hex << tmpPC << "\n";
        }
        if (op != UndefineOP)
          BlockBound = ptc.regs[op];
      }
    }

    if (!isloop)
      break;
  }
}

void JumpTargetManager::harvestStaticAddr(llvm::BasicBlock *thisBlock) {
  BasicBlock::iterator I(thisBlock->begin());
  BasicBlock::iterator end(thisBlock->end());

  for (; I != end; I++) {
    if (I->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(&*I);
      auto v = store->getValueOperand();
      if (dyn_cast<ConstantInt>(v)) {
        auto pc = getLimitedValue(v);
        if (isGOT(pc) and *ptc.isIndirectJmp)
          StaticAddrs[*ptc.isIndirectJmp] = false;
        // Harvest virtual function table targets
        if (VirtualTable) {
          if (isROData(pc))
            harvestVirtualTableAddr(thisBlock, pc);
        }
        // Harvest entry addresses stored in data segment
        StaticAddrsMap::iterator TargetIt = JumpTableBase.find(pc);
        if (isGlobalData(pc) and TargetIt == JumpTableBase.end()) {

          AssignGadge AG(pc);
          assign_gadge.push_back({ pc, AG });
          AllGlobalAddr[pc] = 1;

          // TODO: Memory-block-base address harvest
          if (isMemoryBlockBase(&*I) and isGlobalDataNoRO(pc))
            AllUnexploreGlobalAddr[pc] = getInstructionPC(&*thisBlock->begin());

          int64_t pos = assign_gadge.size() - 1;
          uint32_t isAdd = 0;
          bool haveBO = false;
          std::tie(isAdd, haveBO) = haveBinaryOperation(&*I);

          if (haveBO) {
            assign_gadge[pos].second.operation_block = thisBlock;
            auto Itt = dyn_cast<llvm::Instruction>(&*I);
            assign_gadge[pos].second.global_I = Itt;
            assign_gadge[pos].second.isloop = isAdd;
            assign_gadge[pos].second.block_addr = getInstructionPC(
              &*thisBlock->begin());
            // if thisBlock is indirect or StaticAddr is stored in registers.
            if (*ptc.isIndirect or *ptc.isIndirectJmp
                or (getStaticAddrfromDestRegs1(&*I, 0) and !isCase1(&*I, pc)
                    //      and !isCase2(&*I)
                    )) {
              assign_gadge[pos].second.static_addr_block = thisBlock;
              assign_gadge[pos].second.operation_block = nullptr;
              AllUnexploreGlobalAddr[pc] = assign_gadge[pos].second.block_addr;
              AllStaticGadget[thisBlock] = 1;
              if (*ptc.isIndirect or *ptc.isIndirectJmp)
                assign_gadge[pos].second.indirect = true;
              harvestCodePointerInDataSegment(pos);
            } else {
              // There have global data by logical operations in thisBlock
              // registers
              auto result = getGlobalDatafromRegs(&*I, pos);
              if (result) {
                AllGadget[thisBlock] = 1;
                assign_gadge[pos].second.end = false;
                AllUnexploreGlobalAddr[pc] = assign_gadge[pos]
                                               .second.block_addr;
              }
              if (!result) {
                assign_gadge[pos].second.operation_block = nullptr;
                assign_gadge[pos].second.global_I = nullptr;
                assign_gadge[pos].second.isloop = 0;
                assign_gadge[pos].second.block_addr = 0;
              }
            }

            /***********************************************
             * case2: no loop operation, direct access
             *        array[i].f()
             *   e.g.,  imul   $0x28,%rax,%rax
             *          mov 0x608d18(%rax),%rax
             *          callq  *0x30(%rax)
             ***********************************************/
            DirectCodePointerHarvest(pos);
          }
        }
        if (!haveTranslatedPC(pc, 0) and !isIllegalStaticAddr(pc)) {
          // Store pc and call helper function
          if (!ishelperPC(&*I))
            StaticAddrs[pc] = false;
        }
      }
    }
  }
}

void JumpTargetManager::handleGlobalDataGadget(
  llvm::BasicBlock *thisBlock,
  std::map<uint32_t, uint64_t> &GloData) {
  BasicBlock::iterator it(thisBlock->begin());
  BasicBlock::iterator end(thisBlock->end());

  for (; it != end; it++) {
    if (it->getOpcode() == Instruction::Load) {
      auto load = dyn_cast<llvm::LoadInst>(it);
      auto v = load->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        auto reg = REGLABLE(number);
        if (reg == UndefineOP)
          continue;

        // If thisBlock only transfer baseGlobal, and there is no operation,
        // skip it.
        uint32_t isadd = 0;
        bool haveBO = false;
        std::tie(isadd, haveBO) = haveBinaryOperation(&*it);

        // Handle unoptimizd block
        if (O0)
          getGloFromTempReg(&*it, GloData);

        auto TargetIt = GloData.find(reg);
        if (TargetIt != GloData.end() and haveBO and !isJumpTabType(&*it)) {

          // Get assign_gadge
          auto baseGlobal = TargetIt->second;
          int64_t i = isRecordGadgetBlock(baseGlobal);
          if (i == -1) {
            AssignGadge AG(baseGlobal);
            assign_gadge.push_back({ baseGlobal, AG });
            AllGlobalAddr[baseGlobal] = 1;
            i = assign_gadge.size() - 1;
          }

          // Preserve this null assign_gadge information
          uint32_t tmpOP = UndefineOP;
          auto tmpBB = assign_gadge[i].second.operation_block;
          auto tmpI = assign_gadge[i].second.global_I;
          tmpOP = assign_gadge[i].second.op;
          auto tmpAdd = assign_gadge[i].second.isloop;
          auto tmpblock_addr = assign_gadge[i].second.block_addr;

          // Assign new info to this assign_gadge
          assign_gadge[i].second.operation_block = thisBlock;
          auto itt = dyn_cast<llvm::Instruction>(it);
          assign_gadge[i].second.global_I = itt;
          assign_gadge[i].second.op = reg;
          assign_gadge[i].second.isloop = isadd;
          assign_gadge[i].second.block_addr = getInstructionPC(
            &*thisBlock->begin());

          // Get static addr or global addr from this assign_gadge operations
          if (*ptc.isIndirect or *ptc.isIndirectJmp
              or getStaticAddrfromDestRegs1(&*it, baseGlobal)) {
            assign_gadge[i].second.static_addr_block = thisBlock;
            assign_gadge[i].second.operation_block = nullptr;
            AllStaticGadget[thisBlock] = 1;
            if (*ptc.isIndirect or *ptc.isIndirectJmp)
              assign_gadge[i].second.indirect = true;
            harvestCodePointerInDataSegment(i);
            break;
          }
          auto result = getGlobalDatafromRegs(&*it, i);
          if (result) {
            assign_gadge[i].second.end = false;
            AllGadget[thisBlock] = 1;
            break;
          }

          // Restore original assign_gadge info
          assign_gadge[i].second.operation_block = tmpBB;
          assign_gadge[i].second.global_I = tmpI;
          assign_gadge[i].second.op = tmpOP;
          assign_gadge[i].second.isloop = tmpAdd;
          assign_gadge[i].second.block_addr = tmpblock_addr;
        } // end if(Targ...
      }
    }
  } //?end for?
}

void JumpTargetManager::handleGlobalStaticAddr(void) {
  isRecordCandidataAddr = true;
  if (AllUnexploreGlobalAddr.empty())
    return;
  if (DebugChainFiles)
    return;

  errs() << "gadget chains in loop"
         << "\n";
  testFunction();
  scanAllUnexplore();
  AllUnexploreGlobalAddr.clear();
  assign_gadge.clear();
  AllSrcToDests.insert(SrcToDests.begin(), SrcToDests.end());
  SrcToDests.clear();
  isRecordCandidataAddr = false;

  loadMultProcessSAs();
}

void JumpTargetManager::scanAllUnexplore() {
  for (auto it : AllUnexploreGlobalAddr) {
    auto base = it.first;

    while (base < (base + SCANWIDTH)) {
      if (!isGlobalData(base))
        break;
      auto pc = *((uint64_t *) base);
      if (!haveTranslatedPC(pc, 0))
        StaticAddrs[pc] = false;
      base = base + 0x8;
    }
  }
}

void JumpTargetManager::loadMultProcessSAs(void) {
  auto Path = outputpath + ".StaticAddrs.csv";
  std::ifstream SAs(Path);
  std::string line;
  grin_assert(SAs, "Couldn't open the StaticAd/drs file");

  while (getline(SAs, line)) {
    std::istringstream addresses(line);
    std::string address;

    // obtain the static address
    addresses >> address;
    uint64_t static_address = std::strtoull(address.c_str(), NULL, 16);
    if (!haveTranslatedPC(static_address, 0)
        and !isIllegalStaticAddr(static_address))
      StaticAddrs[static_address] = false;
  }
}

bool JumpTargetManager::isGOT(uint64_t pc) {
  if (DataSegmStartAddr < pc and pc < Binary.dataStartAddr)
    return true;
  return false;
}

bool JumpTargetManager::isROData(uint64_t pc) {
  if (ro_StartAddr == pc)
    return true;
  if (ro_StartAddr < pc and pc < ro_EndAddr)
    return true;

  return false;
}

bool JumpTargetManager::isGlobalData(uint64_t pc) {
  if (DataSegmStartAddr < pc and pc < DataSegmEndAddr)
    return true;
  if (ro_StartAddr < pc and pc < ro_EndAddr)
    return true;

  return false;
}

bool JumpTargetManager::isGlobalDataNoRO(uint64_t pc) {
  if (DataSegmStartAddr < pc and pc < DataSegmEndAddr)
    return true;

  return false;
}

bool JumpTargetManager::haveDefOperation(llvm::Instruction *I, llvm::Value *v) {
  BasicBlock::reverse_iterator it(I);
  BasicBlock::reverse_iterator rend = I->getParent()->rend();

  for (; it != rend; it++) {
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(&*it);
      if (store->getPointerOperand() == v)
        return true;
    }
  }
  return false;
}

bool JumpTargetManager::haveDef2OP(llvm::Instruction *I, uint32_t op) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();

  /* If op is UndefineOP, the base explicit exist gadget block,
   * we consider no loop deadlock. */
  if (op == UndefineOP)
    return true;
  for (; it != end; it++) {
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(&*it);
      auto v = store->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        auto reg = REGLABLE(number);
        if (reg == op)
          return true;
      }
    }
  }
  return false;
}

bool JumpTargetManager::isRecordGlobalBase(uint64_t base) {
  std::map<uint64_t, uint32_t>::iterator Target = AllGlobalAddr.find(base);
  if (Target != AllGlobalAddr.end())
    return true;

  return false;
}

int64_t JumpTargetManager::isRecordGadgetBlock(uint64_t base) {
  //  std::map<llvm::BasicBlock *,uint32_t>::iterator Target =
  //  AllGadget.find(gadget); if(Target!=AllGadget.end())
  //      return -2;

  for (unsigned i = assign_gadge.size();; i--) {
    if (assign_gadge[i].first == base) {
      if (assign_gadge[i].second.operation_block == nullptr
          and assign_gadge[i].second.static_addr_block == nullptr)
        return (int64_t) i;
    }
    if (i == 0)
      break;
  }

  return -1;
}

bool JumpTargetManager::isJumpTabType(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  bool flag = false;
  for (; it != end; it++) {
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(&*it);
      auto v = store->getValueOperand();
      if (dyn_cast<ConstantInt>(v)) {
        auto pc = getLimitedValue(v);
        if (pc > codeSeg_StartAddr
            and (pc < text_StartAddr or pc >= ro_StartAddr))
          flag = true;
      }
    }
    if (it->getOpcode() == Instruction::Call) {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        break;
    }
  }
  return flag;
}

bool JumpTargetManager::ishelperPC(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  auto store = dyn_cast<llvm::StoreInst>(I);
  auto v = store->getPointerOperand();

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        return false;
      break;
    }
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          if (v->getName() == "pc")
            return true;
        }
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for

  return false;
}

bool JumpTargetManager::isMemoryBlockBase(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  auto store = dyn_cast<llvm::StoreInst>(I);
  auto v = store->getPointerOperand();
  bool isMBB = true;

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        return isMBB;
      break;
    }
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          if (op == UndefineOP)
            isMBB = false;
        }
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(inttoptrI);
        isMBB = false;
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for

  return isMBB;
}

// If this value have a binary operation and assign to reg/mem.
std::pair<uint32_t, bool>
JumpTargetManager::haveBinaryOperation(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  bool flag = false;
  bool inttoptrflag = false;
  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Add: {
      auto add = dyn_cast<Instruction>(it);
      if ((add->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      } else if ((add->getOperand(1) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      }
      break;
    }
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        if (flag or inttoptrflag)
          return { 0, false };
      flag = false;
      inttoptrflag = false;
      break;
    }
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (flag or inttoptrflag) {
          if (dyn_cast<Constant>(v)) {
            if (*ptc.isAdd == getInstructionPC(&*it))
              return { 1, true };
            // handle 'lea', e.g.: lea 0x10(base),%rdx
            auto op = getOP(v);
            if (!inttoptrflag and op != UndefineOP) {
              if (isGlobalData(ptc.regs[op]))
                return { 2, true };
            }
            return { 0, true };
          }
        }
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(inttoptrI);
        inttoptrflag = true;
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for
  return { 0, false };
}

void JumpTargetManager::haveGlobalDatainRegs(
  std::map<uint32_t, uint64_t> &GloData) {
  for (int i = 0; i < 16; i++) {
    if (isGlobalData(ptc.regs[i])) {
      if (isRecordGlobalBase(ptc.regs[i])) {
        std::map<uint32_t, uint64_t>::iterator Target = GloData.find(i);
        if (Target == GloData.end())
          GloData[i] = ptc.regs[i];
      } else {
        AssignGadge AG(ptc.regs[i]);
        assign_gadge.push_back({ ptc.regs[i], AG });
        AllGlobalAddr[ptc.regs[i]] = 1;
        GloData[i] = ptc.regs[i];
      }
    }
  }
}

uint32_t JumpTargetManager::getOP(llvm::Value *v) {
  StringRef name = v->getName();
  auto number = StrToInt(name.data());
  return REGLABLE(number);
}

bool JumpTargetManager::getGlobalDatafromRegs(llvm::Instruction *I,
                                              int64_t pre) {
  bool result = false;
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());
  bool flag = false;
  bool inttoptrflag = false;

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          if (op == UndefineOP)
            continue;
          if (isGlobalData(ptc.regs[op]) and (flag or inttoptrflag)) {
            if (!isRecordGlobalBase(ptc.regs[op])) {
              AllGlobalAddr[ptc.regs[op]] = 1;
            }
            AssignGadge AG(ptc.regs[op]);
            AG.pre = pre;
            assign_gadge.push_back({ ptc.regs[op], AG });
            result = true;
          }
        }
      }
      break;
    }
    case llvm::Instruction::Add: {
      auto add = dyn_cast<Instruction>(it);
      if ((add->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      } else if ((add->getOperand(1) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(inttoptrI);
        inttoptrflag = true;
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for
  if (result)
    return result;
  return false;
}

uint64_t JumpTargetManager::getGlobalDatafromDestRegs(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());
  bool flag = false;
  bool inttoptrflag = false;

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          auto op = getOP(v);
          if (op == UndefineOP)
            continue;
          if (isGlobalData(ptc.regs[op]) and (flag or inttoptrflag))
            return ptc.regs[op];
        }
      }
      break;
    }
    case llvm::Instruction::Add: {
      auto add = dyn_cast<Instruction>(it);
      if ((add->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      } else if ((add->getOperand(1) - v) == 0) {
        v = dyn_cast<Value>(add);
        if (!flag)
          flag = true;
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(inttoptrI);
        inttoptrflag = true;
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for

  return 0;

  //  for(;it!=end;it++){
  //    //Only look for dest register
  //    if(it->getOpcode()==Instruction::Store){
  //      auto store = dyn_cast<llvm::StoreInst>(it);
  //      auto v = store->getPointerOperand();
  //      if(dyn_cast<Constant>(v)){
  //       StringRef name = v->getName();
  //       auto number = StrToInt(name.data());
  //       auto op = REGLABLE(number);
  //       if(op==UndefineOP)
  //         continue;
  //       if(isGlobalData(ptc.regs[op])){
  //         return ptc.regs[op];
  //       }
  //      }
  //    }
  //  }//?end for?
}

// Case1: Load static address from global, and store this value to global
bool JumpTargetManager::isCase1(llvm::Instruction *I, uint64_t global) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  Value *v1 = nullptr;
  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      if ((load->getPointerOperand() - v1) == 0)
        v1 = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if (dyn_cast<ConstantInt>(store->getValueOperand())) {
        auto addr = getLimitedValue(store->getValueOperand());
        if (addr == global)
          v1 = store->getPointerOperand();
      }
      if ((store->getValueOperand() - v) == 0)
        v = store->getPointerOperand();
      if ((store->getValueOperand() - v1) == 0)
        v1 = store->getPointerOperand();
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
        if ((InstV - v1) == 0) {
          v1 = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
    if (v == v1)
      return true;
  } //??end for
  return false;
}

// Case2: Load value from global, and add a static addr from a reg to the reg
//          [global] + reg(static) to reg
bool JumpTargetManager::isCase2(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  Value *v1 = nullptr;
  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      return false;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      if ((load->getPointerOperand() - v1) == 0)
        v1 = dyn_cast<Value>(it);
      auto RegV = load->getPointerOperand();
      if (dyn_cast<Constant>(RegV)) {
        StringRef name = RegV->getName();
        auto number = StrToInt(name.data());
        auto op = REGLABLE(number);
        if (op == UndefineOP)
          continue;
        if (isExecutableAddress(ptc.regs[op]))
          v1 = dyn_cast<Value>(it);
      }
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0)
        v = store->getPointerOperand();
      if ((store->getValueOperand() - v1) == 0)
        v1 = store->getPointerOperand();
      break;
    }
    case llvm::Instruction::Add: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0)
          v = dyn_cast<Value>(instr);
        if ((InstV - v1) == 0)
          v1 = dyn_cast<Value>(instr);
      }
      if (v == v1)
        return true;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0)
          v = dyn_cast<Value>(instr);
        if ((InstV - v1) == 0)
          v1 = dyn_cast<Value>(instr);
      }
    }
    }
  } //??end for
  return false;
}

bool JumpTargetManager::getStaticAddrfromDestRegs1(llvm::Instruction *I,
                                                   uint64_t global) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  bool flag = false;
  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          if (op == UndefineOP)
            continue;
          if (isGlobalDataNoRO(global) and ptc.regs[op] == 0 and flag)
            return true;
          if (isExecutableAddress(ptc.regs[op]))
            return true;
        }
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        flag = true;
        v = dyn_cast<Value>(inttoptrI);
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for
  return false;
}

uint64_t JumpTargetManager::getStaticAddrfromDestRegs(
  llvm::Instruction *I,
  uint64_t bound,
  std::pair<uint64_t, uint32_t> &entryinfo) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }
  bool flag = false;
  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          if (op == UndefineOP)
            continue;
          if (isExecutableAddress(ptc.regs[op])) {
            // obtain entry information.
            if (CFG)
              entryinfo = { getInstructionPC(&*it), op };
            return ptc.regs[op];
          }
          if (ptc.regs[op] == 0)
            flag = true;
        }
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for
  if (flag)
    return 0;

  return 1;
}
uint64_t JumpTargetManager::getStaticAddrfromDestRegs(llvm::Instruction *I,
                                                      uint64_t bound) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }
  bool flag = false;
  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call:
      break;
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          if (op == UndefineOP)
            continue;
          if (isExecutableAddress(ptc.regs[op]))
            return ptc.regs[op];
          if (ptc.regs[op] == 0)
            flag = true;
        }
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
    }
  } //??end for
  if (flag)
    return 0;

  return 1;
}

bool JumpTargetManager::isIllegalStaticAddr(uint64_t pc) {
  if (ro_StartAddr <= pc and pc < ro_EndAddr)
    return true;

  if (IllegalStaticAddrs.empty()) {
    return false;
  }
  for (auto addr : IllegalStaticAddrs) {
    if (pc >= addr)
      return true;
  }

  return false;
}

void JumpTargetManager::harvestNextAddrofBr() {

  if (Statistics or CFG) {
    if (*ptc.isDirectJmp) {
      IndirectBlocksMap::iterator it = DirectJmpBlocks.find(*ptc.CFIAddr);
      if (it == DirectJmpBlocks.end())
        DirectJmpBlocks[*ptc.CFIAddr] = 1;
    }
    if (*ptc.isIndirectJmp) {
      IndirectBlocksMap::iterator it = IndirectJmpBlocks.find(*ptc.CFIAddr);
      if (it == IndirectJmpBlocks.end())
        IndirectJmpBlocks[*ptc.CFIAddr] = 1;
    }
    if (*ptc.isIndirect) {
      IndirectBlocksMap::iterator it = IndirectCallBlocks.find(*ptc.CFIAddr);
      if (it == IndirectCallBlocks.end())
        IndirectCallBlocks[*ptc.CFIAddr] = 1;
    }
    if (*ptc.isRet) {
      IndirectBlocksMap::iterator it = RetBlocks.find(*ptc.CFIAddr);
      if (it == RetBlocks.end())
        RetBlocks[*ptc.CFIAddr] = 1;
    }
  }
}

void JumpTargetManager::InitialOutput(std::string OutputPath) {

  outputpath = OutputPath;

  auto JTPath = outputpath + ".JumpTable.log";
  std::ofstream JumpTableAddrInfoStream(JTPath);
  JumpTableAddrInfoStream << "Jump Table Addr:\n";

  auto SAPath = outputpath + ".StaticAddrs.csv";
  std::ofstream StaticAddrsInfoStream(SAPath);

  auto InfoPath = outputpath + ".EntryInfo.csv";
  std::ofstream EntryInfoStream(InfoPath);
  EntryInfoStream << "SrcAddr, AddrOfReg, reg, entry: \n";
}

void JumpTargetManager::StatisticsLog(std::string OutputPath) {
  if (DebugChainFiles) {
    auto SrcToDestsPath = OutputPath + ".SrcToDests.csv";
    std::ofstream SrcToDestsFile;
    SrcToDestsFile.open(SrcToDestsPath,
                        std::ofstream::out | std::ofstream::trunc);
    for (auto it : SrcToDests) {
      SrcToDestsFile << std::hex << it.first;
      for (auto d : it.second) {
        SrcToDestsFile << " " << std::hex << d;
      }
      SrcToDestsFile << "\n";
    }
    SrcToDestsFile.close();

    auto SrcToDestsWithNextPath = OutputPath + ".SrcToDestsWithNext.csv";
    std::ofstream SrcToDestsWithNextFile;
    SrcToDestsWithNextFile.open(SrcToDestsWithNextPath,
                                std::ofstream::out | std::ofstream::trunc);
    for (auto it : SrcToDestsWithNext) {
      SrcToDestsWithNextFile << std::hex << it.first;
      for (auto d : it.second) {
        SrcToDestsWithNextFile << " " << std::hex << d;
      }
      SrcToDestsWithNextFile << "\n";
    }
    SrcToDestsWithNextFile.close();

    auto AllUnexploreGlobalAddrPath = OutputPath
                                      + ".AllUnexploreGlobalAddr.csv";
    std::ofstream AllUnexploreGlobalAddrFile;
    AllUnexploreGlobalAddrFile.open(AllUnexploreGlobalAddrPath,
                                    std::ofstream::out | std::ofstream::trunc);
    for (auto it : AllUnexploreGlobalAddr) {
      AllUnexploreGlobalAddrFile << std::hex << it.first << " " << std::hex
                                 << it.second << "\n";
    }
    AllUnexploreGlobalAddrFile.close();

    auto assign_gadgePath = OutputPath + ".assign_gadge.csv";
    std::ofstream assign_gadgeFile;
    assign_gadgeFile.open(assign_gadgePath,
                          std::ofstream::out | std::ofstream::trunc);
    for (auto it : assign_gadge) {
      assign_gadgeFile << std::hex << it.first;
      assign_gadgeFile << " " << it.second.global_addr;
      assign_gadgeFile << " " << it.second.pre;
      assign_gadgeFile << " " << (uint64_t) it.second.global_I;
      assign_gadgeFile << " " << it.second.op;
      assign_gadgeFile << " " << it.second.block_addr;
      assign_gadgeFile << " " << (uint64_t) it.second.operation_block;
      assign_gadgeFile << " " << (uint64_t) it.second.static_addr_block;
      assign_gadgeFile << " " << (uint64_t) it.second.static_global_I;
      assign_gadgeFile << " " << it.second.static_op;
      assign_gadgeFile << " " << it.second.indirect;
      assign_gadgeFile << " " << it.second.isloop;
      assign_gadgeFile << " " << it.second.end << "\n";
    }
    assign_gadgeFile.close();
  }

  if (!Statistics)
    return;
  outs() << "---------------------------------------\n";
  outs() << "Indirect Calls:"
         << "                " << IndirectCallBlocks.size() << "\n";
  outs() << "Indirect Jumps:"
         << "                " << IndirectJmpBlocks.size() << "\n";
  outs() << "Direct Jumps:"
         << "                " << DirectJmpBlocks.size() + 1 << "\n";
  outs() << "Returns:"
         << "                       " << RetBlocks.size() << "\n";
  outs() << "\n";
  outs() << "Jump Tables of Call:"
         << "           " << CallTable.size() << "\n";
  outs() << "Jump Tables of Jmp:"
         << "            " << JmpTable.size() << "\n";
  outs() << "\n";
  outs() << "Call Branches:"
         << "                 " << CallBranches.size() << "\n";
  outs() << "Cond. Branches:"
         << "                " << CondBranches.size() << "\n";
}

bool JumpTargetManager::handleStaticAddr(void) {
  if (UnexploreStaticAddr.empty()) {
    StaticToUnexplore();
    if (UnexploreStaticAddr.empty()) {
      handleGlobalStaticAddr();
      StaticToUnexplore();
    }
  }
  uint64_t addr = 0;
  uint32_t flag = false;
  while (!UnexploreStaticAddr.empty()) {
    auto it = UnexploreStaticAddr.begin();
    addr = it->first;
    flag = it->second;
    if (haveTranslatedPC(addr, 0) or isIllegalStaticAddr(addr)) {
      if (flag == 2)
        CallNextToStaticAddr(it->first);
      UnexploreStaticAddr.erase(it);
      if (UnexploreStaticAddr.empty()) {
        StaticToUnexplore();
      }
    } else {
      registerJT(addr, JTReason::GlobalData);
      UnexploreStaticAddr.erase(it);
      break;
    }
  }

  return flag;
}

void JumpTargetManager::StaticToUnexplore(void) {
  for (auto &PC : StaticAddrs) {
    BlockMap::iterator TargetIt = JumpTargets.find(PC.first);
    if (TargetIt == JumpTargets.end() and !isIllegalStaticAddr(PC.first)) {
      errs() << format_hex(PC.first, 0) << " <- static address\n";
      UnexploreStaticAddr[PC.first] = PC.second;
    }
    if (TargetIt != JumpTargets.end() and PC.second == 2)
      CallNextToStaticAddr(PC.first);
  }
  StaticAddrs.clear();
}

void JumpTargetManager::CallNextToStaticAddr(uint32_t PC) {
  BasicBlock *Block = obtainJTBB(PC, JTReason::DirectJump);
  BasicBlock::iterator it = Block->begin();
  BasicBlock::iterator end = Block->end();
  uint32_t count = 0;
  if (Block != nullptr) {
    for (; it != end; it++) {
      if (it->getOpcode() == llvm::Instruction::Call) {
        auto callI = dyn_cast<CallInst>(&*it);
        auto *Callee = callI->getCalledFunction();
        if (Callee != nullptr && Callee->getName() == "newpc") {
          auto addr = getLimitedValue(callI->getArgOperand(0));
          count++;
          if (count > 3)
            return;
          StaticAddrs[addr] = false;
          // errs()<<format_hex(pc,0)<<" <- No Crash point, to explore next
          // addr.\n";
        }
      }
    }
  }
}

void JumpTargetManager::handleIndirectCall(llvm::BasicBlock *thisBlock,
                                           uint64_t thisAddr,
                                           bool StaticFlag) {
  IndirectBlocksMap::iterator it = IndirectCallBlocks.find(thisAddr);
  if (it != IndirectCallBlocks.end()) {
    return;
  }
  IndirectCallBlocks[thisAddr] = 1;

  if (StaticFlag)
    return;

  uint32_t userCodeFlag = 0;
  uint32_t &userCodeFlag1 = userCodeFlag;

  // Contains indirect instruction's Block, it must have a store instruction.
  BasicBlock::iterator I = --thisBlock->end();
  if (dyn_cast<BranchInst>(I))
    return;
  errs() << "indirect call&&&&&\n";
  I--;
  auto store = dyn_cast<llvm::StoreInst>(--I);
  if (store) {
    range = 0;
    // Seeking Value of assign to pc.
    // eg:store i64 value, i64* @pc
    NODETYPE nodetmp = nodepCFG;
    std::vector<llvm::Instruction *> DataFlow1;
    std::vector<llvm::Instruction *> &DataFlow = DataFlow1;
    getIllegalValueDFG(store->getValueOperand(),
                       dyn_cast<llvm::Instruction>(store),
                       thisBlock,
                       DataFlow,
                       InterprocessMode,
                       userCodeFlag1);
    errs() << "Finished analysis indirect Inst access Data Flow!\n";
    nodepCFG = nodetmp;

    std::vector<legalValue> legalSet1;
    std::vector<legalValue> &legalSet = legalSet1;
    analysisLegalValue(DataFlow, legalSet);

    // Log information.
    for (auto set : legalSet) {
      for (auto ii : set.I)
        errs() << *ii << " -------------";
      errs() << "\n";
      for (auto vvv : set.value)
        errs() << *vvv << " +++++++++++\n";

      errs() << "\n";
    }
    // To match base+offset mode.
    bool isJmpTable = false;
    for (unsigned i = 0; i < legalSet.size(); i++) {
      if (legalSet[i].I[0]->getOpcode() == Instruction::Add) {
        if (((i + 1) < legalSet.size())
            and (legalSet[i + 1].I[0]->getOpcode() == Instruction::Shl)) {
          legalSet.back().value[0] = dyn_cast<Value>(legalSet.back().I[0]);
          legalSet.erase(legalSet.begin() + i + 2, legalSet.end() - 1);
          isJmpTable = true;
          break;
        }
      }
      for (unsigned j = 0; j < legalSet[i].I.size(); j++) {
        if (legalSet[i].I[j]->getOpcode() == Instruction::Add) {
          if (((j + 1) < legalSet[i].I.size())
              and (legalSet[i].I[j + 1]->getOpcode() == Instruction::Shl)) {
            isJmpTable = true;
            // grin_abort("Not implement!\n");
            return;
          }
        }
      }
    }
    if (isJmpTable) {
      // To assign a legal value
      for (uint64_t n = 0;; n++) {
        auto addrConst = foldSet(legalSet, n);
        if (addrConst == nullptr)
          break;
        auto integer = dyn_cast<ConstantInt>(addrConst);
        auto newaddr = integer->getZExtValue();
        if (newaddr == 0)
          continue;
        if (isExecutableAddress(newaddr))
          harvestBTBasicBlock(thisBlock, thisAddr, newaddr);
        else
          break;
      }
      if (Statistics) {
        IndirectBlocksMap::iterator it = CallTable.find(thisAddr);
        if (it == CallTable.end())
          CallTable[thisAddr] = 1;
      }
    }
  }
}

bool JumpTargetManager::isAccessMemInst(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());
  auto v = dyn_cast<llvm::Value>(I);
  if (I->getOpcode() == Instruction::Store) {
    auto store = dyn_cast<llvm::StoreInst>(I);
    v = store->getPointerOperand();
  }

  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0)
        return true;
      break;
    }
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc") {
        it = lastInst;
        auto pc = getLimitedValue(callI->getArgOperand(0));
        errs() << format_hex(pc, 0)
               << " <- No Crash point, to explore next addr.\n";
      }
      if (Callee != nullptr
          && (Callee->getName() == "helper_fldt_ST0"
              || Callee->getName() == "helper_fstt_ST0"
              || Callee->getName() == "helper_divq_EAX"
              || Callee->getName() == "helper_idivl_EAX"))
        return true;
      break;
    }
    case llvm::Instruction::Load: {
      auto loadI = dyn_cast<llvm::LoadInst>(it);
      if ((loadI->getPointerOperand() - v) == 0)
        v = dyn_cast<Value>(it);
      break;
    }
    case llvm::Instruction::Store: {
      auto storeI = dyn_cast<llvm::StoreInst>(it);
      if ((storeI->getValueOperand() - v) == 0)
        v = storeI->getPointerOperand();
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0)
          v = dyn_cast<Value>(instr);
      }
    }
    }
  }
  return false;
}

uint32_t JumpTargetManager::REGLABLE(uint32_t RegOP) {
  switch (RegOP) {
  case RAX:
    return R_EAX;
    break;
  case RCX:
    return R_ECX;
    break;
  case RDX:
    return R_EDX;
    break;
  case RBX:
    return R_EBX;
    break;
  case RBP: {
    // memset((void *)(ptc.regs[R_ESP]+8),0,1<12);
    return R_EBP;
    break;
  }
  case RSP:
    return R_ESP;
  case RSI:
    return R_ESI;
    break;
  case RDI:
    return R_EDI;
    break;
  case R8:
    return R_8;
    break;
  case R9:
    return R_9;
    break;
  case R10:
    return R_10;
    break;
  case R11:
    return R_11;
    break;
  case R12:
    return R_12;
    break;
  case R13:
    return R_13;
    break;
  case R14:
    return R_14;
    break;
  case R15:
    return R_15;
    break;
  default:
    return UndefineOP;
  }
}

bool JumpTargetManager::isReachtoCurrent(llvm::StoreInst *store,
                                         llvm::Instruction *cur) {
  auto I = dyn_cast<Instruction>(store);
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  BasicBlock::iterator lastInst(I->getParent()->back());

  auto v = store->getPointerOperand();
  auto addr = getInstructionPC(cur);

  bool inttoptrflag = false;
  bool flag = false;
  uint64_t pc = 0;
  it++;
  for (; it != end; it++) {
    switch (it->getOpcode()) {
    case llvm::Instruction::Call: {
      auto callI = dyn_cast<CallInst>(&*it);
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc") {
        pc = getLimitedValue(callI->getArgOperand(0));
        if (pc == addr)
          flag = true;
      }
      break;
    }
    case llvm::Instruction::Load: {
      auto load = dyn_cast<llvm::LoadInst>(it);
      if ((load->getPointerOperand() - v) == 0) {
        if (flag and !inttoptrflag)
          return true;
        v = dyn_cast<Value>(it);
      }
      break;
    }
    case llvm::Instruction::Store: {
      auto store = dyn_cast<llvm::StoreInst>(it);
      if ((store->getValueOperand() - v) == 0) {
        if (flag and !inttoptrflag)
          return true;
        v = store->getPointerOperand();
        if (dyn_cast<Constant>(v)) {
          StringRef name = v->getName();
          auto number = StrToInt(name.data());
          auto op = REGLABLE(number);
          // Exclude the influence of instructions' flag
          if (op == UndefineOP and !inttoptrflag)
            return true;
        }
      }
      break;
    }
    case llvm::Instruction::IntToPtr: {
      auto inttoptrI = dyn_cast<Instruction>(it);
      if ((inttoptrI->getOperand(0) - v) == 0) {
        v = dyn_cast<Value>(inttoptrI);
        // We don't want dereferences involved in the reachable path.
        inttoptrflag = true;
      }
      break;
    }
    default: {
      auto instr = dyn_cast<Instruction>(it);
      for (Use &u : instr->operands()) {
        Value *InstV = u.get();
        if ((InstV - v) == 0) {
          if (flag and !inttoptrflag)
            return true;
          v = dyn_cast<Value>(instr);
          break;
        }
      }
    }
      if (pc > addr)
        break;
    }
  } //??end for
  return false;
}
std::pair<uint32_t, uint64_t>
JumpTargetManager::getLastOperandandNextPC(llvm::Instruction *I,
                                           llvm::Instruction *current) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  uint32_t op = UndefineOP;
  uint64_t addr = 0;
  auto cur_addr = getInstructionPC(current);
  it++;
  for (; it != end; it++) {
    // if(it->getOpcode() == Instruction::Load){
    //  auto load = dyn_cast<LoadInst>(&*it);
    //  load->get
    //}
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<StoreInst>(&*it);
      auto v = store->getPointerOperand();
      if (dyn_cast<Constant>(v) and op == UndefineOP) {
        if (dyn_cast<ConstantInt>(v))
          continue;
        if (!isReachtoCurrent(store, current))
          continue;
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        op = REGLABLE(number);
      }
    }
    if (it->getOpcode() == Instruction::Call) {
      auto call = dyn_cast<CallInst>(&*it);
      grin_assert(call);
      auto *Callee = call->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc") {
        addr = getLimitedValue(call->getArgOperand(0));
        if (addr == cur_addr or op != UndefineOP)
          break;
      }
    }
  }

  return std::make_pair(op, addr);
}

uint32_t JumpTargetManager::getOffsetReg(llvm::Instruction *I) {
  BasicBlock::reverse_iterator it(I);
  BasicBlock::reverse_iterator rend = I->getParent()->rend();
  bool flag = false;
  for (; it != rend; it++) {
    if (it->getOpcode() == Instruction::Shl)
      flag = true;
    if (it->getOpcode() == Instruction::Load) {
      auto load = dyn_cast<LoadInst>(&*it);
      auto v = load->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        auto op = REGLABLE(number);
        if (flag and op != UndefineOP)
          return op;
      }
    }
  }
  return UndefineOP;
}

std::vector<uint32_t> JumpTargetManager::getIndexReg(llvm::Instruction *I) {
  BasicBlock::iterator it(I);
  BasicBlock::iterator end = I->getParent()->end();
  std::vector<uint32_t> OPs;

  it++;
  for (; it != end; it++) {
    if (it->getOpcode() == Instruction::Load) {
      auto load = dyn_cast<LoadInst>(&*it);
      auto v = load->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        auto op = REGLABLE(number);
        if (op != UndefineOP)
          OPs.push_back(op);
      }
    }
    if (it->getOpcode() == Instruction::Call) {
      auto call = dyn_cast<CallInst>(&*it);
      auto *Callee = call->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc")
        break;
    }
  }

  return OPs;
}

uint64_t JumpTargetManager::getInstructionPC(llvm::Instruction *I) {
  BasicBlock::reverse_iterator it(I);
  BasicBlock::reverse_iterator rend = I->getParent()->rend();

  for (; it != rend; it++) {
    auto callI = dyn_cast<CallInst>(&*it);
    if (callI) {
      auto *Callee = callI->getCalledFunction();
      if (Callee != nullptr && Callee->getName() == "newpc") {
        return getLimitedValue(callI->getArgOperand(0));
        // errs()<<format_hex(pc,0)<<" <- Crash Instruction Address.\n";
      }
      if (Callee != nullptr and Callee->getName() == "helper_raise_exception")
        return 0;
    }
  }
  return 0;
}

BasicBlock *JumpTargetManager::getSplitedBlock(llvm::BranchInst *branch) {
  grin_assert(!branch->isConditional());
  auto bb = dyn_cast<BasicBlock>(branch->getOperand(0));
  auto call = dyn_cast<CallInst>(bb->begin());
  auto *Callee = call->getCalledFunction();
  if (Callee != nullptr && Callee->getName() == "newpc") {
    auto PC = getLimitedValue(call->getArgOperand(0));
    // This Crash instruction PC is the start address of this block.
    ToPurge.insert(bb);
    Unexplored.push_back(BlockWithAddress(PC, bb));
    return bb;
  }
  return nullptr;
}

uint64_t
JumpTargetManager::handleIllegalMemoryAccess(llvm::BasicBlock *thisBlock,
                                             uint64_t thisAddr,
                                             size_t ConsumedSize) {

  BasicBlock::iterator endInst = thisBlock->end();

  BasicBlock::iterator lastInst = endInst;
  lastInst--;

  auto PC = getInstructionPC(dyn_cast<Instruction>(lastInst));
  if (PC == thisAddr or PC == 0 or *ptc.isSyscall)
    return thisAddr + ConsumedSize;
  return PC;

  //  //TODO: modify these
  //  uint32_t userCodeFlag = 0;
  //  uint32_t &userCodeFlag1 = userCodeFlag;
  //  BasicBlock::iterator beginInst = thisBlock->begin();
  //  BasicBlock::iterator endInst = thisBlock->end();
  //  BasicBlock::iterator I = beginInst;
  //
  //  if(*ptc.isIndirect || *ptc.isIndirectJmp || *ptc.isRet)
  //    return nullptr;
  //
  //  bool islegal = false;
  //  uint32_t registerOP = 0;
  //
  //  /* Instruction access memory type:
  //   * case 1:  [reg + imm + imm] 10+1+1;
  //   * case 2:  [reg + imm]       10+1
  //   * case 3:  [reg + reg + imm] 10+10+1;
  //   * case 4:  [reg + reg]       10+10 */
  //  uint32_t accessNUM = 0;
  //  BasicBlock::iterator lastInst = endInst;
  //  lastInst--;
  //  if(!dyn_cast<BranchInst>(lastInst)){
  //    auto PC = getInstructionPC(dyn_cast<Instruction>(lastInst));
  //    if(PC == thisAddr)
  //      return nullptr;
  //    return registerJT(PC,JTReason::GlobalData);
  //  }
  //  if(FAST){
  //    return nullptr;
  //  }
  //
  //  I = ++beginInst;
  //  for(; I!=endInst; I++){
  //    if(I->getOpcode() == Instruction::Load){
  //        auto load = dyn_cast<llvm::LoadInst>(I);
  //        Value *V = load->getPointerOperand();
  //	if(dyn_cast<Constant>(V)){
  //            std::tie(islegal,registerOP) = islegalAddr(V);
  //	    if(!islegal and registerOP==RSP){
  //	      haveBB = 1;
  //	      return nullptr;
  //	    }
  //            if(registerOP != 0 &&
  //               isAccessMemInst(dyn_cast<llvm::Instruction>(I)))
  //                accessNUM = accessNUM+10;
  //	}
  //    }
  //    if(I->getOpcode() == Instruction::Store){
  //        auto store = dyn_cast<llvm::StoreInst>(I);
  //	Value *constV = store->getValueOperand();
  //	auto imm = dyn_cast<ConstantInt>(constV);
  //	if(imm){
  //	    if(isAccessMemInst(dyn_cast<llvm::Instruction>(I))){
  //	      if(isExecutableAddress(imm->getZExtValue()))
  //	        accessNUM = accessNUM+10;
  //	      else
  //		accessNUM = accessNUM+1;
  //	    }
  //	}
  //    }
  //    if(I->getOpcode() == Instruction::Call){
  //        auto callI = dyn_cast<CallInst>(&*I);
  //        auto *Callee = callI->getCalledFunction();
  //        if(Callee != nullptr && Callee->getName() == "newpc"){
  //          if(accessNUM > 11){
  //            auto PC = getLimitedValue(callI->getArgOperand(0));
  //	    grin_assert(PC != thisAddr);
  //	    return registerJT(PC,JTReason::GlobalData);
  //	  }
  //          else
  //            accessNUM = 0;
  //        }
  //    }
  //  }
  //  if(accessNUM > 11){
  //    BasicBlock::iterator brI = endInst;
  //    brI--;
  //    auto branch = dyn_cast<BranchInst>(brI);
  //    if(branch){
  //      return getSplitedBlock(branch);
  //    }
  //  }
  //
  //  grin_assert(accessNUM < 12);
  //  I = beginInst;
  //  std::vector<llvm::Instruction *> DataFlow1;
  //  std::vector<llvm::Instruction *> &DataFlow = DataFlow1;
  //  NODETYPE nodetmp = nodepCFG;
  //  for(;I!=endInst;I++){
  //    // case 1: load instruction
  //    if(I->getOpcode() == Instruction::Load){
  //        errs()<<*I<<"         <-Load \n";
  //        auto linst = dyn_cast<llvm::LoadInst>(I);
  //        Value *v = linst->getPointerOperand();
  //        std::tie(islegal,registerOP) = islegalAddr(v);
  //        if(!islegal and isAccessMemInst(dyn_cast<llvm::Instruction>(I))){
  //          if(registerOP == RSP){
  //	    haveBB = 1;
  //	    IllegalStaticAddrs.push_back(thisAddr);
  //	    return nullptr;
  //	  }
  //          getIllegalValueDFG(v,dyn_cast<llvm::Instruction>(I),
  //			  thisBlock,DataFlow,CrashMode,userCodeFlag1);
  //          errs()<<"Finished analysis illegal access Data Flow!\n";
  //          break;
  //        }
  //    }
  //  }
  //  nodepCFG = nodetmp;
  //
  //  // If crash point is not found, choosing one of branches to execute.
  //  if(I==endInst){
  //      BasicBlock::iterator brI = endInst;
  //      brI--;
  //      auto branch = dyn_cast<BranchInst>(brI);
  //      if(branch){
  //	if(!branch->isConditional())
  //          return getSplitedBlock(branch);
  //	else{
  //          auto bb = dyn_cast<BasicBlock>(brI->getOperand(1));
  //          auto br = dyn_cast<BranchInst>(--bb->end());
  //          while(br){
  //            bb = dyn_cast<BasicBlock>(br->getOperand(0));
  //            br = dyn_cast<BranchInst>(--bb->end());
  //          }
  //	  auto PC = getDestBRPCWrite(bb);
  //	  grin_assert(PC != 0);
  //	  auto block =  registerJT(PC,JTReason::GlobalData);
  //	  if(haveBB){
  //            //If chosen branch have been executed, setting havveBB=0,
  //	    // to harvest this Block next.
  //	    haveBB = 0;
  //	    return nullptr;
  //	  }
  //	  else
  //	    return block;
  //	}
  //
  //      }
  //  }
  //
  //  if(I==endInst){////////////////////////////////////////////
  //	  errs()<<format_hex(ptc.regs[R_14],0)<<" r14\n";
  //	  errs()<<format_hex(ptc.regs[R_15],0)<<" r15\n";
  //	  errs()<<*thisBlock<<"\n";}//////////////////////////
  //  //grin_assert(I!=endInst);
  //
  //  std::vector<legalValue> legalSet1;
  //  std::vector<legalValue> &legalSet = legalSet1;
  //  analysisLegalValue(DataFlow,legalSet);
  //  //Log information.
  //  for(auto set : legalSet){
  //    for(auto ii : set.I)
  //      errs()<<*ii<<" -------------";
  //    errs()<<"\n";
  //    for(auto vvv : set.value)
  //      errs() <<*vvv<<" +++++++++++\n";
  //
  //    errs()<<"\n";
  //  }
  //
  //  if(!legalSet.empty()){
  //    auto lastSet = legalSet.back();
  //    auto v = lastSet.value.front();
  //    auto constv = dyn_cast<ConstantInt>(v);
  //    if(constv){
  //      auto global = constv->getZExtValue();
  //      if(isDataSegmAddr(global))
  //          *((uint64_t *) global) = ptc.regs[R_ESP];
  //    }
  //  }
  //
  //  if(I!=endInst){
  //    auto lable = REGLABLE(registerOP);
  //    if(lable == UndefineOP)
  //      grin_abort("Unkown register OP!\n");
  //    ptc.regs[lable] = ptc.regs[R_ESP];
  //  }
  //
  //  llvm::BasicBlock *Block = nullptr;
  //  auto PC = getInstructionPC(dyn_cast<Instruction>(I));
  //  grin_assert(isExecutableAddress(PC));
  //  if(PC == thisAddr){
  //      for(; I!=endInst; I++){
  //        if(I->getOpcode() == Instruction::Call){
  //          auto callI = dyn_cast<CallInst>(&*I);
  //          auto *Callee = callI->getCalledFunction();
  //          if(Callee != nullptr && Callee->getName() == "newpc"){
  //            auto nextPC = getLimitedValue(callI->getArgOperand(0));
  //	    return registerJT(nextPC,JTReason::GlobalData);
  //	  }
  //        }
  //      }
  //      BasicBlock::iterator brI = endInst;
  //      brI--;
  //      auto branch = dyn_cast<BranchInst>(brI);
  //      if(branch){
  //        return getSplitedBlock(branch);
  //      }
  //      grin_assert(I != endInst);
  //      // This Crash instruction PC is the start address of this block.
  //      //ToPurge.insert(thisBlock);
  //      //Unexplored.push_back(BlockWithAddress(thisAddr, thisBlock));
  //      //Block = thisBlock;
  //  }
  //  else
  //      Block = registerJT(PC,JTReason::GlobalData);
  //
  //  return Block;
}

void JumpTargetManager::handleIndirectJmp(llvm::BasicBlock *thisBlock,
                                          uint64_t thisAddr,
                                          bool StaticFlag) {
  uint32_t userCodeFlag = 0;
  uint32_t &userCodeFlag1 = userCodeFlag;
  IndirectJmpBlocks[thisAddr] = 1;

  if (SUPERFAST and StaticFlag)
    return;

  // Contains indirect instruction's Block, it must have a store instruction.
  BasicBlock::iterator I = --thisBlock->end();
  I--;
  auto store = dyn_cast<llvm::StoreInst>(--I);
  if (store) {
    range = 0;
    // Seeking Value of assign to pc.
    // eg:store i64 value, i64* @pc
    NODETYPE nodetmp = nodepCFG;
    std::vector<llvm::Instruction *> DataFlow1;
    std::vector<llvm::Instruction *> &DataFlow = DataFlow1;
    getIllegalValueDFG(store->getValueOperand(),
                       dyn_cast<llvm::Instruction>(store),
                       thisBlock,
                       DataFlow,
                       JumpTableMode,
                       userCodeFlag1);
    errs() << "Finished analysis indirect Inst access Data Flow!\n";
    nodepCFG = nodetmp;

    std::vector<legalValue> legalSet1;
    std::vector<legalValue> &legalSet = legalSet1;
    analysisLegalValue(DataFlow, legalSet);

    // Log information.
    for (auto set : legalSet) {
      for (auto ii : set.I)
        errs() << *ii << " -------------";
      errs() << "\n";
      for (auto vvv : set.value)
        errs() << *vvv << " +++++++++++\n";

      errs() << "\n";
    }

    // To match base+offset mode.
    bool isJmpTable = false;
    for (unsigned i = 0; i < legalSet.size(); i++) {
      if (legalSet[i].I[0]->getOpcode() == Instruction::Add) {
        if (((i + 1) < legalSet.size())
            and (legalSet[i + 1].I[0]->getOpcode() == Instruction::Shl)) {
          legalSet.back().value[0] = dyn_cast<Value>(legalSet.back().I[0]);
          legalSet.erase(legalSet.begin() + i + 2, legalSet.end() - 1);
          isJmpTable = true;
          break;
        }
      }
      for (unsigned j = 0; j < legalSet[i].I.size(); j++) {
        if (legalSet[i].I[j]->getOpcode() == Instruction::Add) {
          if (((j + 1) < legalSet[i].I.size())
              and (legalSet[i].I[j + 1]->getOpcode() == Instruction::Shl)) {
            isJmpTable = true;
            return;
            // grin_abort("Not implement!\n");
          }
        }
      }
    }
    if (!isJmpTable) {
      errs() << "This indirect jmp is not jmp table type.\n";
      return;
    }

    if (Statistics) {
      IndirectBlocksMap::iterator it = JmpTable.find(thisAddr);
      if (it == JmpTable.end())
        JmpTable[thisAddr] = 1;
    }

    range = getLegalValueRange(thisBlock);
    errs() << range << " <---range\n";
    if (range == 0) {
      // grin_abort("Not implement and 'range == 0'\n");
      for (uint64_t n = 0;; n++) {
        auto addrConst = foldSet(legalSet, n);
        if (addrConst == nullptr)
          break;
        auto integer = dyn_cast<ConstantInt>(addrConst);
        auto newaddr = integer->getZExtValue();
        if (newaddr == 0)
          continue;
        if (isExecutableAddress(newaddr))
          harvestBTBasicBlock(thisBlock, thisAddr, newaddr);
        else
          break;
      }
      return;
    }
    // To assign a legal value
    for (uint64_t n = 0; n <= range; n++) {
      auto addrConst = foldSet(legalSet, n);
      if (addrConst == nullptr)
        return;
      auto integer = dyn_cast<ConstantInt>(addrConst);
      harvestBTBasicBlock(thisBlock, thisAddr, integer->getZExtValue());
    }
  }
}

// Harvest branch target(destination) address
void JumpTargetManager::harvestBTBasicBlock(llvm::BasicBlock *thisBlock,
                                            uint64_t thisAddr,
                                            uint64_t destAddr) {
  std::set<uint64_t>::iterator Target = BranchAddrs.find(destAddr);
  if (Target != BranchAddrs.end())
    return;

  if (!haveTranslatedPC(destAddr, 0)) {
    if (!ptc.is_stack_addr(ptc.regs[R_ESP])
        and ptc.is_stack_addr(ptc.regs[R_EBP]))
      ptc.regs[R_ESP] = ptc.regs[R_EBP];
    // if(isDataSegmAddr(ptc.regs[R_ESP]) and !isDataSegmAddr(ptc.regs[R_EBP]))
    //    ptc.regs[R_EBP] = ptc.regs[R_ESP] + 256;
    if (!ptc.is_stack_addr(ptc.regs[R_ESP])
        and !ptc.is_stack_addr(ptc.regs[R_EBP])) {
      ptc.regs[R_ESP] = *ptc.ElfStartStack - 512;
      ptc.regs[R_EBP] = ptc.regs[R_ESP] + 256;
    }
    auto successed = ptc.storeCPUState();
    if (!successed)
      grin_abort("Store CPU stat failed!\n");
    /* Recording not execute branch destination relationship with current
     * BasicBlock */
    // thisBlock = nullptr;
    BranchTargets.push_back(std::make_tuple(destAddr, thisBlock, thisAddr));
    BranchAddrs.insert(destAddr);
    errs() << format_hex(destAddr, 0) << " <- Jmp target add\n";
  }
  errs() << "Branch targets total numbers: " << BranchTargets.size() << "\n";
}

void JumpTargetManager::handleIllegalJumpAddress(llvm::BasicBlock *thisBlock,
                                                 uint64_t thisAddr) {
  if (*ptc.isRet || *ptc.isIndirectJmp)
    return;

  uint32_t userCodeFlag = 0;
  uint32_t &userCodeFlag1 = userCodeFlag;

  // Some bb may be splitted, so tracking to the end bb of splitted.
  auto br = dyn_cast<BranchInst>(--thisBlock->end());
  while (br) {
    thisBlock = dyn_cast<BasicBlock>(br->getOperand(0));
    if (thisBlock == nullptr)
      return;
    br = dyn_cast<BranchInst>(--thisBlock->end());
  }
  // Emerge illegal next jump address, current Block must contain a indirect
  // instruction!
  BasicBlock::iterator I = --thisBlock->end();
  I--;
  auto store = dyn_cast<llvm::StoreInst>(--I);
  if (store) {
    range = 0;
    // Seeking Value of assign to pc.
    // eg:store i64 value, i64* @pc
    NODETYPE nodetmp = nodepCFG;
    std::vector<llvm::Instruction *> DataFlow1;
    std::vector<llvm::Instruction *> &DataFlow = DataFlow1;
    getIllegalValueDFG(store->getValueOperand(),
                       dyn_cast<llvm::Instruction>(store),
                       thisBlock,
                       DataFlow,
                       FullMode,
                       userCodeFlag1);
    errs() << "Finished analysis illegal jump Data Flow!\n";
    nodepCFG = nodetmp;

    std::vector<legalValue> legalSet1;
    std::vector<legalValue> &legalSet = legalSet1;
    analysisLegalValue(DataFlow, legalSet);

    // if(*ptc.isIndirectJmp)
    //   range = getLegalValueRange(thisBlock);

    for (auto set : legalSet) {
      for (auto ii : set.I)
        errs() << *ii << " -------------";
      errs() << "\n";
      for (auto vvv : set.value)
        errs() << *vvv << " +++++++++++\n";

      errs() << "\n";
    }

    // Determine whether is dead code, eg: call 0
    if (legalSet.size() == 1) {
      errs() << "This jump address is a dead code.\n";
      return;
    }

    // To assign a legal value
    auto addrConst = foldSet(legalSet, 0);
    if (addrConst == nullptr)
      return;
    auto integer = dyn_cast<ConstantInt>(addrConst);
    harvestBTBasicBlock(thisBlock, thisAddr, integer->getZExtValue());
  }
}

uint32_t JumpTargetManager::getLegalValueRange(llvm::BasicBlock *thisBlock) {
  llvm::Function::iterator nodeBB(thisBlock);
  llvm::Function::iterator begin(thisBlock->getParent()->begin());

  llvm::BasicBlock *rangeBB = nullptr;
  std::map<llvm::BasicBlock *, llvm::BasicBlock *> DoneOFPath1;
  std::map<llvm::BasicBlock *, llvm::BasicBlock *> &DoneOFPath = DoneOFPath1;
  DoneOFPath[std::get<0>(nodepCFG)] = std::get<1>(nodepCFG);
  // We set a backtrack window to control the loop.
  for (int i = 0; i < 20; i++) {
    auto bb = dyn_cast<llvm::BasicBlock>(nodeBB);
    BasicBlock::iterator I = --(bb->end());
    if (auto branch = dyn_cast<BranchInst>(I)) {
      if (branch->isConditional()) {
        rangeBB = bb;
        break;
      }
    }

    if ((std::get<0>(nodepCFG) - bb) == 0) {
      bb = std::get<1>(nodepCFG);
      llvm::Function::iterator it(bb);
      // Handle split Block
      nodeBB = it;
      searchpartCFG(DoneOFPath);
      while (true) {
        auto I = --(bb->end());
        auto branch = dyn_cast<BranchInst>(I);
        if (branch && !branch->isConditional())
          bb = dyn_cast<BasicBlock>(branch->getOperand(0));
        else
          break;
      }
      auto endI = --(bb->end());
      if (auto branch = dyn_cast<BranchInst>(endI)) {
        if (branch->isConditional()) {
          rangeBB = bb;
          break;
        }
      }
    }
    nodeBB--;
  }

  if (rangeBB == nullptr)
    return 0;

  BasicBlock::iterator I = --rangeBB->end();
  auto br = dyn_cast<BranchInst>(I);
  auto cmp = dyn_cast<ICmpInst>(br->getCondition());
  grin_assert(cmp, "That should a cmp instruction!");
  CmpInst::Predicate p = cmp->getPredicate();
  if (p == CmpInst::ICMP_EQ || p == CmpInst::ICMP_NE) {
    *ptc.isIndirectJmp = 0;
    return 0;
  }

  uint32_t userFlag = 1;
  uint32_t &userFlag1 = userFlag;
  std::vector<llvm::Instruction *> DataFlow1;
  std::vector<llvm::Instruction *> &DataFlow = DataFlow1;
  getIllegalValueDFG(br->getCondition(),
                     dyn_cast<llvm::Instruction>(br),
                     rangeBB,
                     DataFlow,
                     RangeMode,
                     userFlag1);

  std::vector<legalValue> legalSet1;
  std::vector<legalValue> &legalSet = legalSet1;
  analysisLegalValue(DataFlow, legalSet);

  // Log information:
  for (auto set : legalSet) {
    for (auto ii : set.I)
      errs() << *ii << " -------------";
    errs() << "\n";
    for (auto vvv : set.value)
      errs() << *vvv << " +++++++++++\n";

    errs() << "\n";
  }

  //  //Determine if there have a range.
  //  //If all values are constant, there is no range.
  //  for(auto set : legalSet){
  //    for(auto value : set.value){
  //      auto constant = dyn_cast<ConstantInt>(value);
  //      if(constant == nullptr)
  //        goto go_on;
  //    }
  //  }
  //  return 0;

  bool firstConst = true;
  for (auto first : legalSet.front().value) {
    auto constant = dyn_cast<ConstantInt>(first);
    if (constant == nullptr)
      firstConst = false;
  }
  if (firstConst) {
    if (legalSet.front().value.size() == 1) {
      auto constant = dyn_cast<ConstantInt>(legalSet.front().value.front());
      grin_assert(constant, "That should a constant value!\n");
      auto n = constant->getZExtValue();
      return n;
    } else {
      grin_abort("To do more implement!\n");
      // foldstack();
      // return n;
    }
  }
  grin_abort("TODO more implement!\n");
  // firstConst ==  false;
  // foldSet(legalSet);
  // return n;
}

void JumpTargetManager::getIllegalValueDFG(
  llvm::Value *v,
  llvm::Instruction *I,
  llvm::BasicBlock *thisBlock,
  std::vector<llvm::Instruction *> &DataFlow,
  TrackbackMode TrackType,
  uint32_t &userCodeFlag) {
  llvm::User *operateUser = nullptr;
  llvm::Value *v1 = nullptr;
  LastAssignmentResult result;
  llvm::Instruction *lastInst = nullptr;
  std::vector<
    std::tuple<llvm::Value *, llvm::User *, llvm::BasicBlock *, NODETYPE>>
    vs;
  vs.push_back(std::make_tuple(v, dyn_cast<User>(I), thisBlock, nodepCFG));
  DataFlow.push_back(I);

  uint32_t NUMOFCONST1 = 0;
  uint32_t &NUMOFCONST = NUMOFCONST1;
  uint32_t NextValueNums = 0;
  if (TrackType == CrashMode) {
    NextValueNums = 20;
  }
  if (TrackType == JumpTableMode)
    NUMOFCONST = 5;
  if (TrackType == InterprocessMode) {
    NextValueNums = 50; // TODO: optimization parameters
    NUMOFCONST = 5;
  }
  if (TrackType == TestMode)
    NUMOFCONST = 30;

  std::map<llvm::BasicBlock *, llvm::BasicBlock *> DoneOFPath1;
  std::map<llvm::BasicBlock *, llvm::BasicBlock *> &DoneOFPath = DoneOFPath1;
  // Get illegal access Value's DFG.
  while (!vs.empty()) {
    llvm::BasicBlock *tmpB = nullptr;
    std::tie(v1, operateUser, tmpB, nodepCFG) = vs.back();
    DoneOFPath.clear();
    DoneOFPath[std::get<0>(nodepCFG)] = std::get<1>(nodepCFG);

    llvm::Function::iterator nodeBB(tmpB);
    llvm::Function::iterator begin(tmpB->getParent()->begin());
    vs.pop_back();

    for (; nodeBB != begin;) {
      auto bb = dyn_cast<llvm::BasicBlock>(nodeBB);
      if (v1->isUsedInBasicBlock(bb)) {
        // Determine whether bb belongs to user code section
        // userCodeFlag = belongToUBlock(bb);
        userCodeFlag = 1;
        std::tie(result, lastInst) = getLastAssignment(v1,
                                                       operateUser,
                                                       bb,
                                                       TrackType,
                                                       NUMOFCONST);
        switch (result) {
        case CurrentBlockValueDef: {
          if (lastInst->getOpcode() == Instruction::Select) {
            auto select = dyn_cast<llvm::SelectInst>(lastInst);
            v1 = select->getTrueValue();
            vs.push_back(std::make_tuple(select->getFalseValue(),
                                         dyn_cast<User>(lastInst),
                                         bb,
                                         nodepCFG));
          } else {
            auto nums = lastInst->getNumOperands();
            for (Use &lastU : lastInst->operands()) {
              Value *lastv = lastU.get();
              vs.push_back(
                std::make_tuple(lastv, dyn_cast<User>(lastInst), bb, nodepCFG));
            }
            v1 = std::get<0>(vs[vs.size() - nums]);
            vs.erase(vs.begin() + vs.size() - nums);
          }
          DataFlow.push_back(lastInst);
          operateUser = dyn_cast<User>(lastInst);
          nodeBB++;
          break;
        }
        case NextBlockOperating: {
          // Judge current BasickBlcok whether reaching partCFG's node
          // if ture, to research partCFG stack and update node
          if ((std::get<0>(nodepCFG) - bb) == 0) {
            uint32_t num = 0;
            auto callBB = std::get<1>(nodepCFG);
            auto brJT = dyn_cast<BranchInst>(--(callBB->end()));
            if (brJT) {
              if (brJT->isConditional() and *ptc.isIndirectJmp) {
                nodeBB = begin;
                continue;
              }
              std::vector<Value *> brNum;
              brNum.push_back(dyn_cast<Value>(brJT));
              while (!brNum.empty()) {
                auto br = dyn_cast<BranchInst>(brNum.back());
                brNum.pop_back();
                if (br and br->isUnconditional()) {
                  // TODO:br->Operands()
                  auto labelB = dyn_cast<BasicBlock>(br->getOperand(0));
                  brNum.push_back(dyn_cast<Value>(--(labelB->end())));
                  num++;
                }
              }
            }
            llvm::Function::iterator it(std::get<1>(nodepCFG));
            nodeBB = it;
            for (; num > 0; num--)
              nodeBB++;
            searchpartCFG(DoneOFPath);
            continue;
          }
          break;
        }
        case CurrentBlockLastAssign: {
          // Only Store instruction can assign a value for Value rather than
          // defined
          auto store = dyn_cast<llvm::StoreInst>(lastInst);
          v1 = store->getValueOperand();
          DataFlow.push_back(lastInst);
          operateUser = dyn_cast<User>(lastInst);
          nodeBB++;
          break;
        }
        case ConstantValueAssign:
          goto NextValue;
          break;
        case UnknowResult:
          grin_abort("Unknow of result!");
          break;
        }

      } ///?if(v1->isUsedInBasicBlock(bb))?
      else {
        if ((std::get<0>(nodepCFG) - bb) == 0) {
          uint32_t num = 0;
          auto callBB = std::get<1>(nodepCFG);
          auto brJT = dyn_cast<BranchInst>(--(callBB->end()));
          if (brJT) {
            if (brJT->isConditional() and *ptc.isIndirectJmp) {
              nodeBB = begin;
              continue;
            }
            std::vector<Value *> brNum;
            brNum.push_back(dyn_cast<Value>(brJT));
            while (!brNum.empty()) {
              auto br = dyn_cast<BranchInst>(brNum.back());
              brNum.pop_back();
              if (br and br->isUnconditional()) {
                // TODO:br->Operands()
                auto labelB = dyn_cast<BasicBlock>(br->getOperand(0));
                brNum.push_back(dyn_cast<Value>(--(labelB->end())));
                num++;
              }
            }
          }
          llvm::Function::iterator it(std::get<1>(nodepCFG));
          nodeBB = it;
          for (; num > 0; num--)
            nodeBB++;

          searchpartCFG(DoneOFPath);
          continue;
        }
      }
      nodeBB--;
    } ///?for(;nodeBB != begin;)?
  NextValue:
    errs() << "Explore next Value of Value of DFG!\n";
    if (TrackType == JumpTableMode)
      NUMOFCONST = 5;
    if (TrackType == InterprocessMode) {
      NUMOFCONST = 1;
      NextValueNums--;
      if (NextValueNums == 0)
        return;
    }
    if (TrackType == CrashMode) {
      // TrackType = RangeMode;
      NextValueNums--;
      if (NextValueNums == 0)
        return;
    }
    continue;
  } ///?while(!vs.empty())?
}

void JumpTargetManager::analysisLegalValue(
  std::vector<llvm::Instruction *> &DataFlow,
  std::vector<legalValue> &legalSet) {
  if (DataFlow.empty())
    return;

  legalValue *relatedInstPtr = nullptr;
  legalValue *&relatedInstPtr1 = relatedInstPtr;

  llvm::Instruction *next = nullptr;
  for (unsigned i = 0; i < DataFlow.size(); i++) {
    if (i == (DataFlow.size() - 1))
      next = nullptr;
    else
      next = DataFlow[i + 1];
    unsigned Opcode = DataFlow[i]->getOpcode();
    switch (Opcode) {
    case Instruction::Load:
    case Instruction::Store:
      handleMemoryAccess(DataFlow[i], next, legalSet, relatedInstPtr1);
      break;
    case Instruction::Select:
      handleSelectOperation(DataFlow[i], next, legalSet, relatedInstPtr1);
      break;
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::And:
    case Instruction::Shl:
    case Instruction::AShr:
    case Instruction::LShr:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::ICmp:
    case Instruction::Mul:
      handleBinaryOperation(DataFlow[i], next, legalSet, relatedInstPtr1);
      break;
      // case llvm::Instruction::ICmp:
    case llvm::Instruction::IntToPtr:
      handleConversionOperations(DataFlow[i], legalSet, relatedInstPtr1);
      break;
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::Trunc:
    case llvm::Instruction::Br:
    case llvm::Instruction::Call:
      break;
    default:
      errs() << *DataFlow[i];
      grin_abort("Unknow of instruction!");
      break;
    }
  }
}

llvm::Constant *
JumpTargetManager::foldSet(std::vector<legalValue> &legalSet, uint64_t n) {
  const DataLayout &DL = TheModule.getDataLayout();
  Constant *base = nullptr;
  // TODO:Fold Set instruction
  for (auto set : make_range(legalSet.rbegin(), legalSet.rend())) {
    auto op = set.I[0]->getOpcode();
    if (op == Instruction::Add) {
      auto RegConst = dyn_cast<ConstantInt>(set.value[0]);
      if (RegConst == nullptr) {
        auto registerOP = StrToInt(set.value[0]->getName().data());
        if (registerOP == RSP)
          return nullptr;
        auto lable = REGLABLE(registerOP);
        if (lable == UndefineOP)
          return nullptr;
        auto first = ConstantInt::get(Type::getInt64Ty(Context),
                                      ptc.regs[lable]);
        set.value[0] = dyn_cast<Value>(first);
      }
    }
    if (set.I.size() > 1 and op != Instruction::Add)
      return nullptr;

    switch (op) {
    case Instruction::Load:
    case Instruction::Store: {
      auto constant = dyn_cast<ConstantInt>(set.value[0]);
      if (constant) {
        // uint64_t address = constant->getZExtValue();
        // auto newoperand = ConstantInt::get(set.I[0]->getType(),address);
        base = dyn_cast<Constant>(set.value[0]);
      } else
        base = ConstantInt::get(Type::getInt64Ty(Context), n);
      break;
    }
    case Instruction::Select:
      // TODO:later
      break;
    case Instruction::Mul: {
      // TODO modifying later. x = a*b
      auto integer1 = dyn_cast<ConstantInt>(set.value[0]);
      if (integer1 == nullptr)
        return nullptr;
      uint64_t a = integer1->getZExtValue();

      auto integer2 = dyn_cast<ConstantInt>(base);
      uint64_t b = integer2->getZExtValue();
      uint64_t x = a * b;
      base = ConstantInt::get(Type::getInt64Ty(Context), x);
      break;
    }
    case Instruction::And:
    case Instruction::Sub:
    case Instruction::Add:
    case Instruction::LShr:
    case Instruction::AShr:
    case Instruction::Or:
    case Instruction::Shl: {
      auto integer = dyn_cast<ConstantInt>(set.value[0]);
      if (integer == nullptr)
        return nullptr;

      Constant *op2 = dyn_cast<Constant>(set.value[0]);
      op2 = ConstantExpr::getTruncOrBitCast(op2,
                                            set.I[0]->getOperand(1)->getType());
      base = ConstantExpr::getTruncOrBitCast(base,
                                             set.I[0]
                                               ->getOperand(0)
                                               ->getType());
      base = ConstantFoldBinaryOpOperands(op, base, op2, DL);
      break;
    }
    case llvm::Instruction::IntToPtr: {
      // auto inttoptr = dyn_cast<IntToPtrInst>(set.I[0]);
      auto integer = dyn_cast<ConstantInt>(base);
      uint64_t address = integer->getZExtValue();
      if (!ptc.isValidExecuteAddr(address)) {
        errs() << "\nYielding an illegal addrress\n";
        continue;
      }
      uint64_t addr = *((uint64_t *) address);
      base = ConstantInt::get(base->getType(), addr);
      break;
    }
    default:
      errs() << *set.I[0] << "\n";
      grin_abort("Unknow fold instruction!");
      break;
    } /// end switch(...
  } /// end for(auto..
  return base;
}

/* TODO: To assign a value
 * According binary executing memory and CPU States setting */
llvm::Value *JumpTargetManager::payBinaryValue(llvm::Value *v) {
  errs() << "\n" << *v << "\n\n";
  llvm::Type *Int64 = IntegerType::get(TheModule.getContext(), 64);
  uint64_t Address = ptc.regs[R_ESP];
  Constant *probableValue = ConstantInt::get(Int64, Address);
  v = dyn_cast<Value>(probableValue);
  errs() << "\n" << *v << "\n\n";

  return v;
}

// To fold Instruction stack and to assign Value to'global variable'.
void JumpTargetManager::foldStack(legalValue *&relatedInstPtr) {
  const DataLayout &DL = TheModule.getDataLayout();

  while (true) {
    Value *last = relatedInstPtr->value.back();
    Value *secondlast = *(relatedInstPtr->value.end() - 2);

    if (dyn_cast<Constant>(last) and dyn_cast<Constant>(secondlast)) {
      if (dyn_cast<ConstantInt>(last) == nullptr) {
        last = payBinaryValue(last);
      }
      if (dyn_cast<ConstantInt>(secondlast) == nullptr) {
        secondlast = payBinaryValue(secondlast);
      }
      // Fold binary instruction
      Instruction *Inst = relatedInstPtr->I.back();

      if (Inst->getOpcode() == Instruction::Select) {
        auto base = secondlast;
        errs() << *base << " <-encount Select instruction add to base\n";
        relatedInstPtr->value.erase(relatedInstPtr->value.end() - 2);
        relatedInstPtr->I.pop_back();
        break;
      }
      // TODO: To loop base until base equal to 0
      Constant *op1 = dyn_cast<Constant>(last);
      Constant *op2 = dyn_cast<Constant>(secondlast);
      op1 = ConstantExpr::getTruncOrBitCast(op1,
                                            Inst->getOperand(0)->getType());
      op2 = ConstantExpr::getTruncOrBitCast(op2,
                                            Inst->getOperand(1)->getType());
      Constant *NewOperand = ConstantFoldBinaryOpOperands(Inst->getOpcode(),
                                                          op1,
                                                          op2,
                                                          DL);

      relatedInstPtr->value.erase(relatedInstPtr->value.end() - 2,
                                  relatedInstPtr->value.end());
      relatedInstPtr->value.push_back(dyn_cast<Value>(NewOperand));
      relatedInstPtr->I.pop_back();
    } else
      break;
  }
}

void JumpTargetManager::set2ptr(llvm::Instruction *next,
                                std::vector<legalValue> &legalSet,
                                legalValue *&relatedInstPtr) {
  for (unsigned i = 0; i < legalSet.size(); i++) {
    for (unsigned v = 0; v < legalSet[i].value.size(); v++) {
      if (isCorrelationWithNext(legalSet[i].value[v], next)) {
        legalSet[i].value.erase(legalSet[i].value.begin() + v);
        relatedInstPtr = &legalSet[i];
      }
    }
  }
}

void JumpTargetManager::handleMemoryAccess(llvm::Instruction *current,
                                           llvm::Instruction *next,
                                           std::vector<legalValue> &legalSet,
                                           legalValue *&relatedInstPtr) {
  auto loadI = dyn_cast<llvm::LoadInst>(current);
  auto storeI = dyn_cast<llvm::StoreInst>(current);
  Value *v = nullptr;

  if (loadI)
    v = loadI->getPointerOperand();
  else if (storeI)
    v = storeI->getValueOperand();

  if (!isCorrelationWithNext(v, next)) {
    /* Reduct Data flow instructions to Value stack and Instruction stack */
    if (relatedInstPtr) {
      relatedInstPtr->value.push_back(v);
      //      auto num = relatedInstPtr->value.size();
      //      if(num>1){
      //        auto last = dyn_cast<Constant>(relatedInstPtr->value[num-1]);
      //        auto secondlast =
      //        dyn_cast<Constant>(relatedInstPtr->value[num-2]); if(last and
      //        secondlast)
      //          foldStack(relatedInstPtr);
      //      }
    } else
      legalSet.emplace_back(PushTemple(v), PushTemple(current));

    // Find out value that is related with unrelated Inst.
    set2ptr(next, legalSet, relatedInstPtr);
  }
}

void JumpTargetManager::handleConversionOperations(
  llvm::Instruction *current,
  std::vector<legalValue> &legalSet,
  legalValue *&relatedInstPtr) {
  if (relatedInstPtr) {
    // relatedInstPtr->value.push_back(current->getOperand(0));
    relatedInstPtr->I.push_back(current);
    return;
  }

  legalSet.emplace_back(PushTemple(current));
}

void JumpTargetManager::handleSelectOperation(llvm::Instruction *current,
                                              llvm::Instruction *next,
                                              std::vector<legalValue> &legalSet,
                                              legalValue *&relatedInstPtr) {
  auto selectI = dyn_cast<llvm::SelectInst>(current);

  if (relatedInstPtr) {
    if (dyn_cast<ConstantInt>(selectI->getFalseValue()) == nullptr)
      relatedInstPtr->value.push_back(selectI->getFalseValue());

    relatedInstPtr->I.push_back(current);
    return;
  }

  // Because we have pushed FalseValue, so TrueValue must be correlation.
  grin_assert(!isCorrelationWithNext(selectI->getFalseValue(), next),
              "That's wrong!");
  legalSet.emplace_back(PushTemple(selectI->getFalseValue()),
                        PushTemple(current));
  // selectI->getTrueValue();
}

void JumpTargetManager::handleBinaryOperation(llvm::Instruction *current,
                                              llvm::Instruction *next,
                                              std::vector<legalValue> &legalSet,
                                              legalValue *&relatedInstPtr) {
  Value *firstOp = current->getOperand(0);
  Value *secondOp = current->getOperand(1);
  bool first = isCorrelationWithNext(firstOp, next);
  bool second = isCorrelationWithNext(secondOp, next);

  if (relatedInstPtr) {
    auto v = first ? secondOp : firstOp;
    if (dyn_cast<ConstantInt>(v) == nullptr)
      relatedInstPtr->value.push_back(v);

    relatedInstPtr->I.push_back(current);
    return;
  }

  if (first) {
    legalSet.emplace_back(PushTemple(secondOp), PushTemple(current));
  } else if (second) {
    legalSet.emplace_back(PushTemple(firstOp), PushTemple(current));
  } else {
    errs() << *next << "\n";
    grin_abort("Must one Value has correlation!");
  }
  grin_assert(((dyn_cast<Constant>(firstOp) && dyn_cast<Constant>(secondOp))
               != 1),
              "That's unnormal Inst!");
}

bool JumpTargetManager::isCorrelationWithNext(llvm::Value *preValue,
                                              llvm::Instruction *Inst) {
  if (Inst == nullptr)
    return 0;

  if (auto storeI = dyn_cast<llvm::StoreInst>(Inst)) {
    if ((storeI->getPointerOperand() - preValue) == 0)
      return 1;
  } else {
    auto v = dyn_cast<llvm::Value>(Inst);
    if ((v - preValue) == 0)
      return 1;
  }

  return 0;
}

uint32_t JumpTargetManager::StrToInt(const char *str) {
  auto len = strlen(str);
  uint32_t dest = 0;
  if (len == 3)
    dest = str[1] * 1000 + str[2];
  else if (len == 2)
    dest = str[1] * 1000;

  return dest;
}

void JumpTargetManager::clearRegs() {
  // reserve function calling conventions regs
  ptc.regs[R_EAX] = 0;
  ptc.regs[R_EBX] = 0;
  ptc.regs[R_10] = 0;
  ptc.regs[R_11] = 0;
  ptc.regs[R_12] = 0;
  ptc.regs[R_13] = 0;
  ptc.regs[R_14] = 0;
  ptc.regs[R_15] = 0;
}

bool JumpTargetManager::haveFuncPointer(uint64_t fp,
                                        llvm::BasicBlock *thisBlock) {
  llvm::BasicBlock::iterator it = thisBlock->begin();
  for (; it != thisBlock->end(); it++) {
    if (it->getOpcode() == Instruction::Store) {
      auto store = dyn_cast<llvm::StoreInst>(&*it);
      auto v = store->getPointerOperand();
      if (dyn_cast<Constant>(v)) {
        StringRef name = v->getName();
        auto number = StrToInt(name.data());
        auto reg = REGLABLE(number);
        if (reg == R_EDI or reg == R_ESI or reg == R_EDX or reg == R_ECX
            or reg == R_8 or reg == R_9) {
          if (fp == ptc.regs[reg])
            return true;
        }
      }
    }
  }
  return false;
}

void JumpTargetManager::recordFunArgs(uint64_t entry,
                                      llvm::BasicBlock *thisBlock) {
  if (!isExecutableAddress(entry))
    return;

  std::vector<uint64_t> args;
  // rdi,rsi,rdx,rcx,r8,r9
  args.push_back(ptc.regs[R_EDI]);
  args.push_back(ptc.regs[R_ESI]);
  args.push_back(ptc.regs[R_EDX]);
  args.push_back(ptc.regs[R_ECX]);
  args.push_back(ptc.regs[R_8]);
  args.push_back(ptc.regs[R_9]);

  std::map<uint64_t, std::vector<uint64_t>>::iterator Target = FuncArgs.find(
    entry);
  if (Target == FuncArgs.end())
    FuncArgs[entry] = args;

  BlockMap::iterator TargetIt = JumpTargets.find(entry);
  if (TargetIt != JumpTargets.end()) {
    for (size_t i = 0; i < args.size(); i++) {
      if (isExecutableAddress(args[i])) {
        auto p = FuncArgs.find(entry);
        StaticAddrsMap::iterator it = StaticAddrs.find(args[i]);
        if (it != StaticAddrs.end()) {
          /* case1: old callback pointer env assign to this callback pointer,
           *        when this function pointer is called  */
          if (isExecutableAddress(p->second[i]))
            RecoverArgs[args[i]] = p->second[i];
          /* if callback pointer is null,
           * continue to execute for getting env */
          // if(p->second[i]==0 and haveFuncPointer(args[i],thisBlock))
          //    RecoverEnv[args[i]] = {entry, args};
        }
      }
    }
  }
}

void JumpTargetManager::recoverArgs(uint64_t entry) {
  if (!isDataSegmAddr(ptc.regs[R_ESP]))
    ptc.regs[R_ESP] = *ptc.ElfStartStack - 512;

  std::map<uint64_t, uint64_t>::iterator Target = RecoverArgs.find(entry);
  if (Target != RecoverArgs.end()) {
    auto p = FuncArgs.find(Target->second);
    if (p == FuncArgs.end())
      return;
    ptc.regs[R_EDI] = p->second[0];
    ptc.regs[R_ESI] = p->second[1];
    ptc.regs[R_EDX] = p->second[2];
    ptc.regs[R_ECX] = p->second[3];
    ptc.regs[R_8] = p->second[4];
    ptc.regs[R_9] = p->second[5];
    return;
  }

  auto it = RecoverEnv.find(entry);
  if (it != RecoverEnv.end())
    getArgsEnv(entry);
}

void JumpTargetManager::getArgsEnv(uint64_t entry) {
  auto it = RecoverEnv.find(entry);

  // set regs env
  ptc.regs[R_EDI] = it->second.second[0];
  ptc.regs[R_ESI] = it->second.second[1];
  ptc.regs[R_EDX] = it->second.second[2];
  ptc.regs[R_ECX] = it->second.second[3];
  ptc.regs[R_8] = it->second.second[4];
  ptc.regs[R_9] = it->second.second[5];

  // Run it
  errs() << "run in loop...\n";
  std::map<uint64_t, std::vector<uint64_t>> branch;
  std::set<uint64_t> Executed;
  uint64_t nextPC = it->second.first;
  uint64_t maxloop = 0;
  errs() << "start: " << nextPC << " args:" << entry << "\n";
  while (nextPC != entry) {
    Executed.insert(nextPC);
    auto pc = ptc.exec(nextPC);

    if ((uint64_t) pc == entry)
      return;
    if (*ptc.isCall) {
      if (ptc.regs[R_EDI] != entry and ptc.regs[R_ESI] != entry
          and ptc.regs[R_EDX] != entry and ptc.regs[R_ECX] != entry
          and ptc.regs[R_8] != entry and ptc.regs[R_9] != entry)
        pc = *ptc.isCall;
    }
    if (pc == -1) {
      auto BB = obtainJTBB(nextPC);
      if (BB == nullptr)
        pc = 0;
      pc = handleIllegalMemoryAccess(BB, nextPC, *ptc.BlockSize);
    }

    std::map<uint64_t, std::set<uint64_t>>::iterator br = CondBranches.find(
      nextPC);
    if (br != CondBranches.end()) {
      for (auto p : br->second) {
        if ((uint64_t) pc != p) {
          storeCPURegister();
          branch[(uint64_t) pc] = TempCPURegister;
        }
      }
    }

    std::set<uint64_t>::iterator ExecutedIt = Executed.find(pc);
    if (ExecutedIt != Executed.end() or !isExecutableAddress(pc)) {
      if (branch.empty())
        return;
      auto begin = branch.begin();
      pc = begin->first;
      TempCPURegister = begin->second;
      recoverCPURegister();
      branch.erase(begin);
    }

    nextPC = pc;
    if ((++maxloop) > 100)
      break;
  }
}

void JumpTargetManager::harvestCallBasicBlock(llvm::BasicBlock *thisBlock,
                                              uint64_t thisAddr) {
  if (!isDataSegmAddr(ptc.regs[R_ESP]))
    ptc.regs[R_ESP] = *ptc.ElfStartStack - 512;
  errs() << *((unsigned long *) ptc.regs[4]) << "<--store callnext\n";
  errs() << *ptc.CallNext << "\n";

  auto it = CallBranches.find(thisAddr);
  if (it == CallBranches.end())
    CallBranches[thisAddr] = *ptc.CallNext;

  // exclude splited block
  BasicBlock::iterator I = --(thisBlock->end());
  auto branch = dyn_cast<BranchInst>(I);
  if (branch == nullptr)
    generatePartCFGWithNext(thisAddr, *ptc.CallNext, thisBlock);

  std::set<uint64_t>::iterator Target = BranchAddrs.find(*ptc.CallNext);
  if (Target != BranchAddrs.end())
    return;

  if (!haveTranslatedPC(*ptc.CallNext, 0)) {
    /* Construct a state that have executed a call to next instruction of CPU
     * state */
    ptc.regs[R_ESP] = ptc.regs[R_ESP] + 8;
    auto success = ptc.storeCPUState();
    if (!success)
      grin_abort("Store CPU stat failed!\n");

    // Recover stack state
    ptc.regs[R_ESP] = ptc.regs[R_ESP] - 8;

    /* Recording not execute branch destination relationship with current
     * BasicBlock */
    /* If we rewrite a Block that instructions of part have been rewritten,
     * this Block ends this rewrite and add a br to jump to already existing
     * Block, So,this Block will not contain a call instruction, that has been
     * splited but we still record this relationship, because when we
     * backtracking, we will check splited Block. */
    BranchTargets.push_back(
      std::make_tuple(*ptc.CallNext, thisBlock, thisAddr));
    BranchAddrs.insert(*ptc.CallNext);
    errs() << format_hex(*ptc.CallNext, 0) << " <- Call next target add\n";
  }
  errs() << "Branch targets total numbers: " << BranchTargets.size() << "\n";
}

void JumpTargetManager::harvestbranchBasicBlock(
  uint64_t nextAddr,
  uint64_t thisAddr,
  llvm::BasicBlock *thisBlock,
  uint32_t size,
  std::map<std::string, llvm::BasicBlock *> &branchlabeledBasicBlock) {
  std::set<uint64_t> branchJT;

  // case 1: New block is belong to part of original block, so to split
  //         original block and occure a unconditional branch.
  //     eg:   size  >= 2
  //           label = 1

  // case 2: New block have a conditional branch, and
  //         contains mutiple label.
  //     eg:   size  >= 2
  //           label >= 2
  // outs()<<"next  "<<format_hex(nextAddr,0)<<"\n";
  BasicBlock::iterator I = --(thisBlock->end());

  if (auto branch = dyn_cast<BranchInst>(I)) {
    if (branch->isConditional()) {
      // outs()<<*I<<"\n";
      grin_assert(size == branchlabeledBasicBlock.size(),
                  "This br block should have many labels!");
      for (auto pair : branchlabeledBasicBlock) {
        if (getDestBRPCWrite(pair.second))
          branchJT.insert(getDestBRPCWrite(pair.second));
      }
    }
  }

  if (!branchJT.empty()) {
    // grin_assert(branchJT.size()==2,"There should have tow jump targets!");
    // If there have one jump target, return it.
    if (branchJT.size() < 2)
      return;

    auto it = CondBranches.find(thisAddr);
    if (it == CondBranches.end())
      CondBranches[thisAddr] = branchJT;

    for (auto destAddrSrcBB : branchJT) {
      if (!haveTranslatedPC(destAddrSrcBB, nextAddr)) {
        bool isRecord = false;
        std::set<uint64_t>::iterator Target = BranchAddrs.find(destAddrSrcBB);
        if (Target != BranchAddrs.end())
          isRecord = true;

        if (!isRecord) {
          /* Recording current CPU state */
          if (!ptc.is_stack_addr(ptc.regs[R_ESP])
              and ptc.is_stack_addr(ptc.regs[R_EBP]))
            ptc.regs[R_ESP] = ptc.regs[R_EBP];
          // if(isDataSegmAddr(ptc.regs[R_ESP]) and
          // !isDataSegmAddr(ptc.regs[R_EBP]))
          //    ptc.regs[R_EBP] = ptc.regs[R_ESP] + 256;
          if (!ptc.is_stack_addr(ptc.regs[R_ESP])
              and !ptc.is_stack_addr(ptc.regs[R_EBP])) {
            ptc.regs[R_ESP] = *ptc.ElfStartStack - 512;
            ptc.regs[R_EBP] = ptc.regs[R_ESP] + 256;
          }
          auto success = ptc.storeCPUState();
          if (!success)
            grin_abort("Store CPU stat failed!\n");

          /* Recording not execute branch destination relationship
           * with current BasicBlock and address */
          BranchTargets.push_back(std::make_tuple(destAddrSrcBB,
                                                  // destAddrSrcBB.second,
                                                  thisBlock,
                                                  thisAddr));
          BranchAddrs.insert(destAddrSrcBB);
          errs() << format_hex(destAddrSrcBB, 0) << " <- Jmp target add\n";
        }
      }
      generatePartCFG(thisAddr, destAddrSrcBB, thisBlock);
      generatePartCFGWithNext(thisAddr, destAddrSrcBB, thisBlock);
    }
    errs() << "Branch targets total numbers: " << BranchTargets.size() << " \n";
  }
}

int64_t JumpTargetManager::getDestBRPCWrite(llvm::BasicBlock *block) {
  BasicBlock::iterator current(block->end());
  BasicBlock::iterator Begin(block->begin());
  while (current != Begin) {
    current--;
    auto Store = dyn_cast<StoreInst>(current);
    if (Store) {
      auto constantvalue = dyn_cast<ConstantInt>(Store->getValueOperand());
      if (constantvalue) {
        auto pc = constantvalue->getSExtValue();
        if (isExecutableAddress(pc) and isInstructionAligned(pc))
          return pc;
      }
    }
  }
  return 0;
}

bool JumpTargetManager::haveTranslatedPC(uint64_t pc, uint64_t next) {
  if (!isExecutableAddress(pc) || !isInstructionAligned(pc))
    return 1;
  if (pc == next)
    return 1;
  // Do we already have a BasicBlock for this pc?
  BlockMap::iterator TargetIt = JumpTargets.find(pc);
  if (TargetIt != JumpTargets.end()) {
    return 1;
  }

  return 0;
}

using BlockWithAddress = JumpTargetManager::BlockWithAddress;
using JTM = JumpTargetManager;
const BlockWithAddress JTM::NoMoreTargets = BlockWithAddress(0, nullptr);

// read the origin cfg, store them int the cfgMap
// SrcToDests: the origin cfg generated during the translation
void CFGMap::generateCFGMap(
  std::map<uint64_t, std::set<uint64_t>> &SrcToDests) {
  // traverse the origin cfg
  for (auto iter = SrcToDests.begin(); iter != SrcToDests.end(); iter++) {
    // get the source address and determine whether it is a text section address
    uint64_t sourceAddress = (*iter).first;

    if (isTextAddress(sourceAddress)) {
      // create a source node
      std::pair<uint64_t const, CFGNode> *sourceNode;
      sourceNode = createNode(sourceAddress);

      // get all the source address's successors
      std::set<uint64_t> successorAddresses = (*iter).second;
      for (auto iter1 = successorAddresses.begin();
           iter1 != successorAddresses.end();
           iter1++) {
        uint64_t successorAddress = *iter1;
        if (isTextAddress(successorAddress)) {
          // create a successor node
          std::pair<uint64_t const, CFGNode> *successorNode;
          successorNode = createNode(successorAddress);

          // insert the edge <source node, successor node>
          insertEdge(sourceNode, successorNode);
        }
      }
    }
  }

  // adjust the node's minAddress, maxAddress and nextBranch
  // traverse cfgMap
  for (std::map<uint64_t, CFGNode>::iterator iter = cfgMap.begin();
       iter != cfgMap.end();
       iter++) {
    std::pair<uint64_t const, CFGNode> *cfgnode = &*iter;
    adjustNode(cfgnode);
  }
  // loop node
  for (std::map<uint64_t, CFGNode>::iterator iter = cfgMap.begin();
       iter != cfgMap.end();
       iter++) {
    std::pair<uint64_t const, CFGNode> *cfgnode = &*iter;
    adjustNullNextBranch(cfgnode);
  }
}

// create one node in the cfgMap, and return the node pointer
std::pair<uint64_t const, CFGMap::CFGNode> *
CFGMap::createNode(uint64_t address) {
  struct CFGNode cfgnode;
  cfgnode.minAddress = address;
  cfgnode.maxAddress = address;
  cfgnode.nextBranch = nullptr;
  std::pair<std::map<uint64_t, CFGNode>::iterator, bool> ret;
  ret = cfgMap.insert(std::pair<uint64_t, CFGNode>(address, cfgnode));
  return &*(ret.first);
}

// insert the edge <source node, successor node>
void CFGMap::insertEdge(std::pair<uint64_t const, CFGNode> *sourceNode,
                        std::pair<uint64_t const, CFGNode> *successorNode) {
  sourceNode->second.successorNodes.insert(successorNode);
  successorNode->second.predecessorNodes.insert(sourceNode);
}

// adjust the node's minAddress, maxAddress and nextBranch
void CFGMap::adjustNode(std::pair<uint64_t const, CFGNode> *cfgnode) {
  adjustNodeAddress(cfgnode);
  adjustNodeNextBranch(cfgnode);
}

// adjust the node's minAddress and maxAddress
void CFGMap::adjustNodeAddress(std::pair<uint64_t const, CFGNode> *node) {
  // Depth-first traversal
  // to adjust all the predecessor
  std::stack<std::pair<uint64_t const, CFGNode> *> adjustNodes;
  adjustNodes.push(node);

  while (!adjustNodes.empty()) {
    // pop node
    std::pair<uint64_t const, CFGNode> *adjustNode;
    adjustNode = adjustNodes.top();
    adjustNodes.pop();

    // get the node's minAddress and maxAddress
    uint64_t minAddress = adjustNode->second.minAddress;
    uint64_t maxAddress = adjustNode->second.maxAddress;

    // get all the node's predecessors
    // if the predecessor adjusted,push it into the stack
    std::set<std::pair<uint64_t const, CFGNode> *>
      predecessorNodes = adjustNode->second.predecessorNodes;
    std::set<std::pair<uint64_t const, CFGNode> *>::iterator iter1;
    for (iter1 = predecessorNodes.begin(); iter1 != predecessorNodes.end();
         iter1++) {
      std::pair<uint64_t const, CFGNode> *predecessorNode = *iter1;

      // get the predeceesor_node's minAddress and maxAddress
      uint64_t predecessorMinAddress = (predecessorNode->second).minAddress;
      uint64_t predecessorMaxAddress = (predecessorNode->second).maxAddress;

      // if predecessor's minAddress more than the node's minAddress,then adjust
      // predecessor
      if (predecessorMinAddress > minAddress) {
        adjustNodes.push(predecessorNode);
        (predecessorNode->second).minAddress = minAddress;
      }
      // the same
      if (predecessorMaxAddress < maxAddress) {
        adjustNodes.push(predecessorNode);
        (predecessorNode->second).maxAddress = maxAddress;
      }
    }
  }
}

// loop node
void CFGMap::adjustNullNextBranch(std::pair<uint64_t const, CFGNode> *node) {
  if (node->second.nextBranch == nullptr)
    node->second.nextBranch = node;
}

// adjust the node's nextBranch
void CFGMap::adjustNodeNextBranch(std::pair<uint64_t const, CFGNode> *node) {
  // whether the node is a branch node
  bool isBranchNode = false;
  std::set<std::pair<uint64_t const, CFGNode> *> successorNodes;
  successorNodes = getSuccessors(node);

  // is branch node or leaf node
  if (successorNodes.size() != 1)
    isBranchNode = true;

  // if the node is a branch node, adjust all the nor branch predecessor nodes.
  if (isBranchNode) {
    // Depth-first traversal
    std::stack<std::pair<uint64_t const, CFGNode> *> adjustNodes;
    adjustNodes.push(node);

    while (!adjustNodes.empty()) {
      std::pair<uint64_t const, CFGNode> *adjustNode;
      // pop node
      adjustNode = adjustNodes.top();
      adjustNodes.pop();

      // adjust the node's nextBranch
      adjustNode->second.nextBranch = node;

      // get the need adjust node's predecessors, if the predecessor is not a
      // branch node, push it into the adjustNodes stack
      std::set<std::pair<uint64_t const, CFGNode> *> predecessorNodes;
      predecessorNodes = getPredecessors(adjustNode);
      for (auto iter = predecessorNodes.begin(); iter != predecessorNodes.end();
           iter++) {
        // whether the predecessor is a branch node
        std::pair<uint64_t const, struct CFGNode> *predecessorNode = *iter;
        std::set<std::pair<uint64_t const, struct CFGNode> *>
          predecessorNode_successors;

        predecessorNode_successors = getSuccessors(predecessorNode);

        // if the predecessor is not a branch node ,push it into the adjustNodes
        // stack
        if (predecessorNode_successors.size() <= 1)
          adjustNodes.push(predecessorNode);
      }
    }
  }
}

// determine whether the address is in the text section
bool CFGMap::isTextAddress(uint64_t address) {
  if ((address >= startAddr) && (address <= endAddr))
    return true;
  else
    return false;
}

// output the cfg
void CFGMap::printCFGMap() {
  int i = 0;
  for (std::map<uint64_t, CFGNode>::iterator iter = cfgMap.begin();
       iter != cfgMap.end();
       iter++) {
    outs() << "第" << i << "个:";
    i++;
    outs() << format_hex(iter->first, 0);
    std::set<std::pair<uint64_t const, struct CFGNode> *>
      successorNodes = getSuccessors(&*iter);

    bool isBranch = (successorNodes.size() > 1) ? true : false;

    for (std::set<std::pair<uint64_t const, struct CFGNode> *>::iterator iter1 =
           successorNodes.begin();
         iter1 != successorNodes.end();
         iter1++) {
      outs() << " " << format_hex((*iter1)->first, 0);
      bool isSuccessorBranch = (getSuccessors(*iter1).size() > 1) ? true :
                                                                    false;

      if (isBranch) {
        // error0: branch's nextBranch doesn't equal the branch
        if (&*iter != iter->second.nextBranch)
          outs() << "\nkkkkkkk0:" << iter->first << &*iter
                 << iter->second.nextBranch;
      }
      if (isSuccessorBranch) {
        // error1: if successor is a branch,this node's next branch is not this
        // successor
        if (*iter1 != (*iter1)->second.nextBranch)
          outs() << "\nkkkkkkk1:" << (*iter1)->first << &*iter1
                 << (*iter1)->second.nextBranch;
      }
      if (!isBranch) {
        // error2: this node's nextBranch is not equal to successor's nextBranch
        if (iter->second.nextBranch != (*iter1)->second.nextBranch)
          outs() << "\nkkkkkkk2:" << iter->first << iter->second.nextBranch
                 << (*iter1)->first << (*iter1)->second.nextBranch;
      }

      // error3: this's node's maxAddress is less than successor's maxAddress
      if (iter->second.maxAddress < (*iter1)->second.maxAddress)
        outs() << "\nkkkkkkk3:" << iter->first << iter->second.maxAddress
               << (*iter1)->first << (*iter1)->second.maxAddress;

      // error4: this's node's maxAddress is less successor's maxAddress
      if (iter->second.minAddress > (*iter1)->second.minAddress)
        outs() << "\nkkkkkkk4:" << iter->first << iter->second.minAddress
               << (*iter1)->first << (*iter1)->second.minAddress;
    }
    outs() << " minAddress:" << format_hex((iter->second).minAddress, 0)
           << " maxAddress:" << format_hex((iter->second).maxAddress, 0);
    outs() << " nextBranch:" << format_hex((iter->second).nextBranch->first, 0);
    if ((iter->second.maxAddress != iter->second.maxAddress)
        && (iter->second.nextBranch == nullptr))
      outs() << "\nkkkkkk5:";
    outs() << " \n";
  }

  outs() << "map size:" << cfgMap.size() << "\n";
}

// insert new cfgnode or edge
void CFGMap::insertNew(uint64_t sourceAddress, uint64_t successorAddress) {
  if (isTextAddress(sourceAddress)) {
    // create a source node
    std::pair<uint64_t const, CFGNode> *sourceNode;
    sourceNode = createNode(sourceAddress);

    if (isTextAddress(successorAddress)) {
      // create a successor node
      std::pair<uint64_t const, CFGNode> *successorNode;
      successorNode = createNode(successorAddress);

      // insert the edge <source node, successor node>
      insertEdge(sourceNode, successorNode);
      adjustNode(sourceNode);
      adjustNode(successorNode);
    }
  }
}

bool CFGMap::isAddressPrecedent(std::set<uint64_t> nextAddresses,
                                uint64_t addr2) {
  bool relationship = false;
  std::pair<uint64_t const, CFGNode> *node2 = getNode(addr2);

  if (node2 != nullptr) {
    std::pair<uint64_t const, CFGNode> *nextBranch;
    nextBranch = node2->second.nextBranch;
    uint64_t nextAddr = nextBranch->first;
    if (nextAddresses.find(nextAddr) != nextAddresses.end())
      relationship = true;
  } else {
    outs() << "can't find the addr in the cfgMap. addr2:" << addr2 << "\n";
  }
  return relationship;
}

// find the addr1 and addr2 's connections
int CFGMap::getAddressOrder(uint64_t addr1, uint64_t addr2) {
  // 0:not meet   1: add1,addr2  2: addr2, addr1
  int relationship = 0;

  std::pair<uint64_t const, CFGNode> *node1 = getNode(addr1);
  std::pair<uint64_t const, CFGNode> *node2 = getNode(addr2);

  if ((node1 != nullptr) && (node2 != nullptr)) {
    relationship = getCfgNodeOrder(node1, node2);
  } else {
    outs() << "can't find the addr in the cfgMap. addr1:" << addr1
           << "  addr2:" << addr2 << "\n";
  }
  return relationship;
}

// find the addr1 and addr2 's connections
void CFGMap::getAddressesOrder(uint64_t addr1,
                               std::map<uint64_t, bool> &addr2s) {
  std::pair<uint64_t const, CFGNode> *node1 = getNode(addr1);

  std::map<std::pair<uint64_t const, CFGNode> *, uint64_t> nodeAddr;
  std::map<std::pair<uint64_t const, CFGNode> *, bool> nodeOrder;

  for (auto iter = addr2s.begin(); iter != addr2s.end(); iter++) {
    uint64_t addr2 = iter->first;
    std::pair<uint64_t const, CFGNode> *node2 = getNode(addr2);
    if ((node1 != nullptr) && (node2 != nullptr)) {
      nodeAddr.insert({ node2, addr2 });
      nodeOrder.insert({ node2, false });
    } else {
      outs() << "can't find the addr in the cfgMap. addr1:" << addr1
             << "  addr2:" << addr2 << "\n";
    }
  }

  getCfgNodeOrders(node1, nodeOrder);

  for (auto iter = nodeOrder.begin(); iter != nodeOrder.end(); iter++) {
    std::pair<uint64_t const, CFGNode> *node = iter->first;
    bool relationship = iter->second;
    uint64_t addr = (nodeAddr.find(node))->second;
    (addr2s.find(addr))->second = relationship;
  }
}

// if node1 ande node2 are in the same branch
int CFGMap::getSameBranchNodeOrder(std::pair<uint64_t const, CFGNode> *node1,
                                   std::pair<uint64_t const, CFGNode> *node2) {
  int relationship = 0;

  std::pair<uint64_t const, CFGNode> *successor1 = node1;
  std::pair<uint64_t const, CFGNode> *successor2 = node2;

  // node1 and node2 search each other at the same time
  while (!relationship) {
    // is this node a branch(or leafnode). a branch's(or leafnode's) nextBranch
    // equal itself
    bool isBranch1 = (successor1->second.nextBranch == successor1) ? true :
                                                                     false;
    bool isBranch2 = (successor2->second.nextBranch == successor2) ? true :
                                                                     false;

    successor1 = *(getSuccessors(successor1).begin());
    successor2 = *(getSuccessors(successor2).begin());
    // node1 meet branch node firstly,represents the distance between
    // <node1,Branch> is shorter than the distance between <node2,Branch>.so
    // node1 is after node2 or node2 meet node1. so node1 is after node2
    if (isBranch1 or (successor2 == node1)) {
      relationship = 2;
      break;
    }
    // the same
    if (isBranch2 or (successor1 == node2)) {
      relationship = 1;
      break;
    }
  }

  return relationship;
}

// put iegal successor branch into nextBranches
void CFGMap::pushIegalSuccessBranches(
  std::queue<std::pair<uint64_t const, CFGNode> *> &nextBranches,
  std::set<std::pair<uint64_t const, CFGNode> *> &allNextBranches,
  std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
    &allNextBranchesSequence,
  std::pair<uint64_t const, CFGNode> *branch,
  uint64_t minAddress,
  uint64_t maxAddress) {
  std::set<std::pair<uint64_t const, CFGNode> *> successorNodes;
  successorNodes = getSuccessors(branch);
  for (auto iter = successorNodes.begin(); iter != successorNodes.end();
       iter++) {
    std::pair<uint64_t const, CFGNode> *successorBranch;
    successorBranch = (*iter)->second.nextBranch;

    if (successorBranch == nullptr)
      continue;

    // De-duplication branches
    std::pair<std::set<std::pair<uint64_t const, CFGNode> *>::iterator, bool>
      ret;
    ret = allNextBranches.insert(successorBranch);
    if (!ret.second)
      continue;

    allNextBranchesSequence.push_back(successorBranch);
    // Pruning unnecessary branch
    uint64_t successorBranchMinAddress = getMinAddress(successorBranch);
    uint64_t successorBranchMaxAddress = getMaxAddress(successorBranch);

    // if (node2_minAddress,node2_maxAddress) is a subset of
    // (branchSuccessor_minAddress, branchSuccessor_maxAddress) then node2 is
    // possible in this branch,otherwise node1 is not possible in this
    // branch,don't need to traverse this branch.
    if (minAddress >= successorBranchMinAddress
        && maxAddress <= successorBranchMaxAddress)
      nextBranches.push(successorBranch);
  }
}

bool CFGMap::isBranchPrecedent(std::pair<uint64_t const, CFGNode> *branch1,
                               std::pair<uint64_t const, CFGNode> *branch2,
                               uint64_t minAddress2,
                               uint64_t maxAddress2) {
  bool relationship = false;

  std::queue<std::pair<uint64_t const, CFGNode> *> nextBranches1;
  std::set<std::pair<uint64_t const, CFGNode> *> allNextBranches1;

  nextBranches1.push(branch1);
  allNextBranches1.insert(branch1);

  // Depth-first traversal
  while (nextBranches1.size()) {
    // Two-way search
    if (nextBranches1.size()) {
      // pop branch
      std::pair<uint64_t const, CFGNode> *branch;
      branch = nextBranches1.front();
      nextBranches1.pop();

      // branch1 meet branch2
      if (branch == branch2) {
        relationship = 1;
        break;
      }

      // push all the not null branch successor into nextBranch
      std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
        allNextBranchesSequence;
      pushIegalSuccessBranches(nextBranches1,
                               allNextBranches1,
                               allNextBranchesSequence,
                               branch,
                               minAddress2,
                               maxAddress2);
    }
  }
  return relationship;
}

// get the order of branch1 and branch2
int CFGMap::getBranchOrder(std::pair<uint64_t const, CFGNode> *branch1,
                           std::pair<uint64_t const, CFGNode> *branch2,
                           uint64_t minAddress1,
                           uint64_t maxAddress1,
                           uint64_t minAddress2,
                           uint64_t maxAddress2) {
  int relationship = 0;

  std::queue<std::pair<uint64_t const, CFGNode> *> nextBranches1;
  std::queue<std::pair<uint64_t const, CFGNode> *> nextBranches2;
  std::set<std::pair<uint64_t const, CFGNode> *> allNextBranches1;
  std::set<std::pair<uint64_t const, CFGNode> *> allNextBranches2;

  nextBranches1.push(branch1);
  allNextBranches1.insert(branch1);

  nextBranches2.push(branch2);
  allNextBranches2.insert(branch2);

  // Depth-first traversal
  while (nextBranches1.size() || nextBranches2.size()) {
    // Two-way search
    if (nextBranches1.size()) {
      // pop branch
      std::pair<uint64_t const, CFGNode> *branch;
      branch = nextBranches1.front();
      nextBranches1.pop();

      // branch1 meet branch2
      if (branch == branch2) {
        relationship = 1;
        break;
      }

      // push all the not null branch successor into nextBranch
      std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
        allNextBranchesSequence;
      pushIegalSuccessBranches(nextBranches1,
                               allNextBranches1,
                               allNextBranchesSequence,
                               branch,
                               minAddress2,
                               maxAddress2);
    }

    if (nextBranches2.size()) {
      // pop node
      std::pair<uint64_t const, CFGNode> *branch;
      branch = nextBranches2.front();
      nextBranches2.pop();

      // node2 meet node1
      if (branch == branch1) {
        relationship = 2;
        break;
      }

      // push all the not null branch successor into nextBranch
      std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
        allNextBranchesSequence;
      pushIegalSuccessBranches(nextBranches2,
                               allNextBranches2,
                               allNextBranchesSequence,
                               branch,
                               minAddress1,
                               maxAddress1);
    }
  }
  return relationship;
}

bool CFGMap::isNodePrecedent(std::pair<uint64_t const, CFGNode> *node1,
                             std::pair<uint64_t const, CFGNode> *node2) {
  bool relationship = false;

  std::pair<uint64_t const, CFGNode> *nextBranch1 = node1->second.nextBranch;
  std::pair<uint64_t const, CFGNode> *nextBranch2 = node2->second.nextBranch;

  // the node1 and node2 are in the same branch
  if (nextBranch1 == nextBranch2) {
    relationship = getSameBranchNodeOrder(node1, node2);
  } else {
    uint64_t minAddress2 = getMinAddress(node2);
    uint64_t maxAddress2 = getMaxAddress(node2);
    // the node1 and node2 are not in the same branch
    relationship = isBranchPrecedent(nextBranch1,
                                     nextBranch2,
                                     minAddress2,
                                     maxAddress2);
  }

  return relationship;
}

// find the addr1 and addr2 's connections
int CFGMap::getCfgNodeOrder(std::pair<uint64_t const, CFGNode> *node1,
                            std::pair<uint64_t const, CFGNode> *node2) {
  int relationship = 0;

  std::pair<uint64_t const, CFGNode> *nextBranch1 = node1->second.nextBranch;
  std::pair<uint64_t const, CFGNode> *nextBranch2 = node2->second.nextBranch;

  // the node1 and node2 are in the same branch
  if (nextBranch1 == nextBranch2) {
    relationship = getSameBranchNodeOrder(node1, node2);
  } else {
    uint64_t minAddress1 = getMinAddress(node1);
    uint64_t minAddress2 = getMinAddress(node2);
    uint64_t maxAddress1 = getMaxAddress(node1);
    uint64_t maxAddress2 = getMaxAddress(node2);
    // the node1 and node2 are not in the same branch
    relationship = getBranchOrder(nextBranch1,
                                  nextBranch2,
                                  minAddress1,
                                  maxAddress1,
                                  minAddress2,
                                  maxAddress2);
  }

  return relationship;
}

// find the addr1 and addr2 's connections
void CFGMap::getCfgNodeOrders(
  std::pair<uint64_t const, CFGNode> *node1,
  std::map<std::pair<uint64_t const, CFGNode> *, bool> nodeOrders) {
  /* int relationship = 0;

   std::pair<uint64_t const, CFGNode> * nextBranch1 = node1->second.nextBranch;

   std::pair<uint64_t const, CFGNode> * nextBranch2 = node2->second.nextBranch;

   //the node1 and node2 are in the same branch
   if (nextBranch1 == nextBranch2)
   {
     relationship = getSameBranchNodeOrder(node1, node2);
   }else{
     uint64_t minAddress1 = getMinAddress(node1);
     uint64_t minAddress2 = getMinAddress(node2);
     uint64_t maxAddress1 = getMaxAddress(node1);
     uint64_t maxAddress2 = getMaxAddress(node2);
     //the node1 and node2 are not in the same branch
     relationship = getBranchOrder(nextBranch1, nextBranch2, minAddress1,
   maxAddress1, minAddress2, maxAddress2);
   }

   return relationship;*/
}

// find oneNode's all nextBranches
std::pair<std::set<std::pair<uint64_t const, CFGMap::CFGNode> *>,
          std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>>
CFGMap::findNextBranches(std::pair<uint64_t const, CFGNode> *node,
                         uint64_t addr,
                         int numbers) {
  std::set<std::pair<uint64_t const, CFGNode> *> allNextBranches;
  std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
    allNextBranchesSequence;
  std::queue<std::pair<uint64_t const, CFGNode> *> nextBranches;
  std::pair<uint64_t const, struct CFGNode> *nextBranch;
  nextBranch = node->second.nextBranch;

  nextBranches.push(nullptr);
  // Depth-first traversal
  nextBranches.push(nextBranch);
  allNextBranches.insert(nextBranch);
  allNextBranchesSequence.push_back(nextBranch);

  uint64_t minAddress = addr;
  uint64_t maxAddress = addr;
  if (addr == 0) {
    minAddress = 0xffffffffffffffff;
    maxAddress = 0x0;
  }

  int layerNumbers = 0;
  while ((nextBranches.size() != 0) && layerNumbers <= numbers) {
    nextBranch = nextBranches.front();
    nextBranches.pop();

    if (nextBranch == nullptr) {
      if (nextBranches.size() == 0)
        break;
      else {
        layerNumbers++;
        nextBranches.push(nullptr);
        continue;
      }
    }

    pushIegalSuccessBranches(nextBranches,
                             allNextBranches,
                             allNextBranchesSequence,
                             nextBranch,
                             minAddress,
                             maxAddress);
  }

  return { allNextBranches, allNextBranchesSequence };
}

// find addr's nextAddresses
void CFGMap::findNextAddresses(uint64_t addr,
                               std::set<uint64_t> &nextAddresses,
                               int numbers) {
  std::pair<uint64_t const, CFGNode> *node = getNode(addr);
  if (node != nullptr) {
    std::set<std::pair<uint64_t const, CFGNode> *> nextBranches;
    nextBranches = findNextBranches(node, 0, numbers).first;

    for (auto iter = nextBranches.begin(); iter != nextBranches.end(); iter++) {
      std::pair<uint64_t const, CFGNode> *nextBranch = *iter;
      nextAddresses.insert(nextBranch->first);
    }
  }
}

// find addr's nextAddresses
void CFGMap::findNextAddressesSequence(uint64_t addr,
                                       std::vector<uint64_t> &nextAddresses,
                                       int numbers) {
  std::pair<uint64_t const, CFGNode> *node = getNode(addr);
  if (node != nullptr) {
    std::vector<std::pair<uint64_t const, CFGNode> *> nextBranches;
    nextBranches = findNextBranches(node, 0, numbers).second;

    for (auto iter = nextBranches.begin(); iter != nextBranches.end(); iter++) {
      std::pair<uint64_t const, CFGNode> *nextBranch = *iter;
      nextAddresses.push_back(nextBranch->first);
    }
  }
}

// find addr1 and addr2's mergeAddress
std::set<uint64_t> CFGMap::findMergeAddress(uint64_t addr1, uint64_t addr2) {
  std::set<uint64_t> mergeAddresses;
  std::pair<uint64_t const, CFGNode> *node1 = getNode(addr1);
  std::pair<uint64_t const, CFGNode> *node2 = getNode(addr2);
  if ((node1 != nullptr) && (node2 != nullptr)) {
    std::set<std::pair<uint64_t const, CFGNode> *> nextBranches1;
    std::set<std::pair<uint64_t const, CFGNode> *> nextBranches2;
    nextBranches1 = findNextBranches(node1, addr2, 0x7FFFFFFF).first;
    nextBranches2 = findNextBranches(node2, addr1, 0x7FFFFFFF).first;

    for (auto iter = nextBranches1.begin(); iter != nextBranches1.end();
         iter++) {
      std::pair<uint64_t const, CFGNode> *nextBranch1 = *iter;
      auto nextBranch2 = nextBranches2.find(nextBranch1);
      if (nextBranch2 != nextBranches2.end())
        mergeAddresses.insert(nextBranch1->first);
    }
  }

  return mergeAddresses;
}

using AssignGadge = JumpTargetManager::AssignGadge;

BaseHeaps::BaseHeaps(
  CFGMap &theCFG,
  CFGMap &theCFGWithNext,
  std::vector<std::pair<uint64_t, AssignGadge>> &assign_gadge,
  std::map<uint64_t, uint64_t> &AllUnexploreGlobalAddr) :
  theCFG(theCFG),
  theCFGWithNext(theCFGWithNext),
  allGadgets(assign_gadge),
  AllUnexploreGlobalAddr(AllUnexploreGlobalAddr) {
  // put related bases and gadgets in one heap
  traverseAllGadgets();
  findUnexploredBases();
}

// insert a primeBase into AllBaseHeaps
std::pair<uint64_t const, BaseHeaps::BaseHeap> *
BaseHeaps::insertBaseHeap(uint64_t primeBase) {
  // can't find primeBase in AllUnexploreGlobalAddr
  if (AllUnexploreGlobalAddr.find(primeBase) == AllUnexploreGlobalAddr.end())
    return nullptr;

  BaseHeap nullBaseHeap;
  nullBaseHeap.firstBaseNode = 0x0;
  // return the pointer of base heap
  auto thisBaseHeap = AllBaseHeaps.insert({ primeBase, nullBaseHeap });

  return &*(thisBaseHeap.first);
}

template<class T>
std::string BaseHeaps::vectorTostring(std::vector<T> &visited, T notVisited) {
  std::stringstream ss;
  std::string ret;
  std::string visitedString;
  for (auto iter = visited.begin(); iter != visited.end(); iter++) {
    T haveVisited = *iter;
    std::stringstream ss;
    ss << haveVisited;
    std::string ret;
    ss >> ret;
    visitedString += ret;
  }
  if (notVisited) {
    std::stringstream ss;
    ss << notVisited;
    std::string ret;
    ss >> ret;
    visitedString += ret;
  }
  return visitedString;
}

template<class T>
void BaseHeaps::adjustVisited(std::map<T, nestedNode<T>> &graph,
                              std::vector<T> &visited,
                              std::pair<T const, nestedNode<T>> *thisNode,
                              std::set<std::string> &chainsSet,
                              std::set<T> &allPrimes,
                              T preKey) {
  if (visited.size() != 0) {
    T tailKey = visited.back();
    auto tailNext = graph.find(tailKey)->second.nextNestedNodes;

    std::string visitedString = vectorTostring(visited, thisNode->first);

    while ((tailKey != preKey || (tailNext.find(thisNode)) == tailNext.end())
           || (chainsSet.find(visitedString) != chainsSet.end())) {
      visited.pop_back();
      if (visited.size() != 0) {
        tailKey = visited.back();
        tailNext = graph.find(tailKey)->second.nextNestedNodes;
        visitedString = vectorTostring(visited, thisNode->first);
      } else {
        break;
      }
    }
  }

  if (visited.size() != 0)
    visited.push_back(thisNode->first);
  else if (allPrimes.find(thisNode->first) != allPrimes.end())
    visited.push_back(thisNode->first);
  else
    outs() << "error base chain!";
}

// convert graph to chain
template<class T>
void BaseHeaps::graphToChains(std::map<T, nestedNode<T>> &graph,
                              std::set<T> &allPrimes,
                              std::vector<std::vector<T>> &chains) {
  // Depth-first traversal
  std::stack<std::pair<T, T>> waiting;
  std::vector<T> visited;
  std::set<std::string> chainsSet;

  // put all the primes
  for (auto iter = allPrimes.begin(); iter != allPrimes.end(); iter++) {
    waiting.push({ *iter, 0 });
  }

  while (!waiting.empty()) {
    T thisKey;
    T preKey;
    thisKey = waiting.top().first;
    preKey = waiting.top().second;
    waiting.pop();

    std::pair<T const, nestedNode<T>> *thisNode;
    thisNode = &*(graph.find(thisKey));
    adjustVisited(graph, visited, thisNode, chainsSet, allPrimes, preKey);

    if (visited.size() != 0) {
      // put next key into waiting.
      std::set<std::pair<T const, nestedNode<T>> *> nextNodes;
      nextNodes = thisNode->second.nextNestedNodes;

      for (auto iter = nextNodes.begin(); iter != nextNodes.end();) {
        std::pair<T const, nestedNode<T>> *nextNode;
        nextNode = *iter;
        int nRet = std::count(visited.begin(), visited.end(), nextNode->first);
        if (nRet == 0) {
          waiting.push({ nextNode->first, thisKey });
          iter++;
        } else
          nextNodes.erase(iter++);
      }

      if ((nextNodes.size() == 0) && (visited.size() > 1)) {
        std::vector<T> chain;
        for (auto iter = visited.begin(); iter != visited.end(); iter++) {
          T key = *iter;
          chain.push_back(key);
        }
        chains.push_back(chain);
        std::string visitedString = vectorTostring(visited, (T) 0);
        chainsSet.insert(visitedString);
      }
    }
  }
}

// insert a base and gadgets into a baseheap
std::pair<uint64_t const, BaseHeaps::BaseNode> *BaseHeaps::insertBaseGadgets(
  std::pair<uint64_t const, BaseHeap> *aBaseHeap,
  std::pair<uint64_t const, std::set<AssignGadge *>> *aBaseGadgets) {
  uint64_t thisBase = aBaseGadgets->first;
  std::set<AssignGadge *> *waitingGadgets = &(aBaseGadgets->second);

  BaseNode nullBaseNode;
  GadgetNode nullGadgetNode;

  // insert thisBase and thisGadgets
  std::map<uint64_t, BaseNode> *AllBasesInHeap = &(
    aBaseHeap->second.basesInHeap);
  auto thisBaseInHeap = AllBasesInHeap->insert({ thisBase, nullBaseNode });
  std::map<AssignGadge *, GadgetNode> *thisGadgets = &(
    thisBaseInHeap.first->second.gadgetsMap);

  for (auto iter = waitingGadgets->begin(); iter != waitingGadgets->end();
       iter++) {
    AssignGadge *thisGadget = *iter;
    auto ret = thisGadgets->insert({ thisGadget, nullGadgetNode });
    aBaseHeap->second.allGadgets.insert(&*(ret.first));
  }

  return &*(thisBaseInHeap.first);
}

uint64_t BaseHeaps::traverseBaseChains(
  std::vector<std::vector<uint64_t>> baseChains,
  std::map<uint64_t, std::set<AssignGadge *>> &allBaseGadgets) {
  // traverse BaseChains
  uint64_t base = 0;
  ThreadPool tp(30);
  std::vector<std::future<
    std::pair<uint64_t,
              std::vector<std::pair<
                std::set<std::pair<AssignGadge *const, GadgetNode> *> *,
                std::pair<AssignGadge *const, GadgetNode> *>>>>>
    v;
  std::mutex mtx;
  std::map<uint64_t, std::set<std::pair<uint64_t, uint64_t>>> handledBases;
  for (auto iter = baseChains.begin(); iter != baseChains.end(); iter++) {
    std::vector<uint64_t> thisBaseChain = *iter;
    /*outs() << "kkbaseChain:";
    for(auto itert = thisBaseChain.begin(); itert != thisBaseChain.end();
    itert++)
    {
      uint64_t value = *itert;
      outs() << " " << format_hex(value, 0);
    }
    outs() << "\n";*/

    if (thisBaseChain.size() > 1) {
      uint64_t primeBase = thisBaseChain.front();
      base = primeBase;

      auto thisBaseHeap = AllBaseHeaps.find(primeBase);
      thisBaseHeap->second.baseChains.push_back(thisBaseChain);
      auto preGadgets = allBaseGadgets.find(primeBase);
      auto preBaseHeap = insertBaseGadgets(&*thisBaseHeap, &*preGadgets);
      thisBaseChain.erase(thisBaseChain.begin());

      std::map<AssignGadge *, GadgetNode> *preGadgetsMap = &(
        preBaseHeap->second.gadgetsMap);
      std::set<std::pair<AssignGadge *const, GadgetNode> *> preAllGadgets;
      std::set<std::pair<AssignGadge *const, GadgetNode> *> preLoopGadgets;
      std::set<std::pair<AssignGadge *const, GadgetNode> *> preNotLoopGadgets;
      std::set<std::pair<uint64_t, uint64_t>> nullHandledBases;
      auto thisHandledBases = &(
        handledBases.insert({ primeBase, nullHandledBases }).first->second);

      bool preIsDivision;
      preIsDivision = loopGadgetsDivision(preGadgetsMap,
                                          preAllGadgets,
                                          preLoopGadgets,
                                          preNotLoopGadgets);

      preBaseHeap->second.isDivision = preIsDivision;
      preBaseHeap->second.loopGadgets = preLoopGadgets;
      preBaseHeap->second.notLoopGadgets = preNotLoopGadgets;

      if (preIsDivision) {
        auto ret = thisHandledBases->find({ primeBase, primeBase });
        if (ret == thisHandledBases->end()) {
          thisHandledBases->insert({ primeBase, primeBase });
          if (BanMultithread)
            gadgetConnection(preLoopGadgets,
                             preNotLoopGadgets,
                             true,
                             primeBase,
                             1,
                             true);
          else {
            try {
              auto ans = tp.add(&BaseHeaps::gadgetConnection,
                                this,
                                preLoopGadgets,
                                preNotLoopGadgets,
                                true,
                                primeBase,
                                1,
                                true);
              v.push_back(std::move(ans));
            } catch (const std::exception &e) {
              outs() << e.what() << '\n';
            }
          }

          // gadgetConnection(preLoopGadgets, preNotLoopGadgets, true);
        }
      } else {
        preBaseHeap->second.loopGadgets = preAllGadgets;
        preBaseHeap->second.notLoopGadgets = preAllGadgets;
      }

      thisBaseHeap->second.firstBaseNode = preBaseHeap;

      uint64_t preBase = primeBase;
      for (auto iter1 = thisBaseChain.begin(); iter1 != thisBaseChain.end();
           iter1++) {
        uint64_t nextBase = *iter1;

        auto nextGadgets = allBaseGadgets.find(nextBase);
        auto nextBaseHeap = insertBaseGadgets(&*thisBaseHeap, &*nextGadgets);

        preBaseHeap->second.nextBaseNodes.insert(nextBaseHeap);

        std::map<AssignGadge *, GadgetNode> *nextGadgetsMap = &(
          nextBaseHeap->second.gadgetsMap);
        std::set<std::pair<AssignGadge *const, GadgetNode> *> nextAllGadgets;
        std::set<std::pair<AssignGadge *const, GadgetNode> *> nextLoopGadgets;
        std::set<std::pair<AssignGadge *const, GadgetNode> *>
          nextNotLoopGadgets;
        bool nextIsDivision;
        nextIsDivision = loopGadgetsDivision(nextGadgetsMap,
                                             nextAllGadgets,
                                             nextLoopGadgets,
                                             nextNotLoopGadgets);

        nextBaseHeap->second.isDivision = nextIsDivision;
        nextBaseHeap->second.loopGadgets = nextLoopGadgets;
        nextBaseHeap->second.notLoopGadgets = nextNotLoopGadgets;

        bool isConnected = (thisHandledBases->find({ preBase, nextBase })
                            != thisHandledBases->end()) ?
                             true :
                             false;

        // connect gadget chain by cfg
        if (!isConnected) {
          thisHandledBases->insert({ preBase, nextBase });
          if (nextIsDivision)
            thisHandledBases->insert({ nextBase, nextBase });

          try {
            if (preIsDivision | (!nextIsDivision)) {
              if (BanMultithread)
                gadgetConnection(preAllGadgets,
                                 nextAllGadgets,
                                 false,
                                 preBase,
                                 2,
                                 true);
              else {
                auto ans = tp.add(&BaseHeaps::gadgetConnection,
                                  this,
                                  preAllGadgets,
                                  nextAllGadgets,
                                  false,
                                  preBase,
                                  2,
                                  true);
                v.push_back(std::move(ans));
              }
              // gadgetConnection(preAllGadgets, nextAllGadgets, false);
            }
            if ((!preIsDivision) & nextIsDivision) {
              if (BanMultithread)
                gadgetConnection(preAllGadgets,
                                 nextLoopGadgets,
                                 false,
                                 preBase,
                                 3,
                                 true);
              else {
                auto ans = tp.add(&BaseHeaps::gadgetConnection,
                                  this,
                                  preAllGadgets,
                                  nextLoopGadgets,
                                  false,
                                  preBase,
                                  3,
                                  true);
                v.push_back(std::move(ans));
              }
              // gadgetConnection(preAllGadgets, nextLoopGadgets, false);
            }
            if (nextIsDivision) {
              if (BanMultithread)
                gadgetConnection(nextLoopGadgets,
                                 nextNotLoopGadgets,
                                 true,
                                 preBase,
                                 4,
                                 preIsDivision);
              else {
                auto ans = tp.add(&BaseHeaps::gadgetConnection,
                                  this,
                                  nextLoopGadgets,
                                  nextNotLoopGadgets,
                                  true,
                                  preBase,
                                  4,
                                  preIsDivision);
                v.push_back(std::move(ans));
              }
              // gadgetConnection(nextLoopGadgets, nextNotLoopGadgets, true);
            }
          } catch (const std::exception &e) {
            outs() << e.what() << '\n';
          }
        }

        preBaseHeap = nextBaseHeap;
        preAllGadgets = nextAllGadgets;
        preLoopGadgets = nextLoopGadgets;
        preNotLoopGadgets = nextNotLoopGadgets;
        preIsDivision = nextIsDivision;
        preBase = nextBase;
        preGadgetsMap = nextGadgetsMap;
      }
    }
  }
  for (size_t i = 0; i < v.size(); ++i) {
    std::lock_guard<std::mutex> lg(mtx);
    auto result = v[i].get();
    std::vector<
      std::pair<std::set<std::pair<AssignGadge *const, GadgetNode> *> *,
                std::pair<AssignGadge *const, GadgetNode> *>>
      gadgetPairs = result.second;
    uint64_t primeBase = result.first;
    for (auto iter = gadgetPairs.begin(); iter != gadgetPairs.end(); iter++) {
      std::set<std::pair<AssignGadge *const, GadgetNode> *> *nextGadgets;
      nextGadgets = (*iter).first;
      std::pair<AssignGadge *const, GadgetNode> *gadget;
      gadget = (*iter).second;
      nextGadgets->insert(gadget);
    }
    outs() << primeBase << '\n';
  }
  return base;
}

// traverse allGadgets
void BaseHeaps::traverseAllGadgets() {
  // traverse allGadgets and put the gadgets of the same base together
  std::map<uint64_t, std::set<AssignGadge *>> allBaseGadgets;
  std::map<uint64_t, nestedNode<uint64_t>> allBaseMap;
  std::map<uint64_t, bool> allBases;
  for (auto iter = allGadgets.begin(); iter != allGadgets.end(); iter++) {
    // gadget is not null
    if (((*iter).second.operation_block != nullptr)
        || ((*iter).second.static_addr_block != nullptr)) {
      std::pair<uint64_t, AssignGadge> *thisBaseGadget = &*iter;
      uint64_t thisBase = thisBaseGadget->first;

      // insert theBase and thisGadget into allBaseGadgets
      std::set<AssignGadge *> nullGadgets;
      auto thisBaseHeap = allBaseGadgets.insert({ thisBase, nullGadgets });

      AssignGadge *thisGadget = &(thisBaseGadget->second);
      thisBaseHeap.first->second.insert(thisGadget);

      // if theBase is not prime Base, store thisBase and preBase into
      // allBaseMap
      int pre = thisGadget->pre;
      if (pre != -1) {
        nestedNode<uint64_t> nullNestedNodes;
        uint64_t preBase = allGadgets[pre].first;

        if (thisBase != preBase) {
          auto thisBaseMap = allBaseMap.insert({ thisBase, nullNestedNodes });
          auto preBaseMap = allBaseMap.insert({ preBase, nullNestedNodes });

          preBaseMap.first->second.nextNestedNodes.insert(
            &*(thisBaseMap.first));
          thisBaseMap.first->second.preNestedNodes.insert(&*(preBaseMap.first));
        }
      }

      auto ret = allBases.insert({ thisBase, true });
      if (ret.first->second && pre != -1)
        ret.first->second = false;
    }
  }

  // put all the primes
  std::set<uint64_t> allPrimes;
  ThreadPool tp(30);
  std::vector<std::future<uint64_t>> v;
  std::mutex mtx;
  for (auto iter = allBaseMap.begin(); iter != allBaseMap.end(); iter++) {
    std::pair<uint64_t const, nestedNode<uint64_t>> *node = &*iter;
    // find primeBase, no preNestedNodes, hash nextNestedNodes
    if ((node->second.preNestedNodes.size() == 0)
        && (node->second.nextNestedNodes.size() != 0)) {
      uint64_t primeBase = node->first;
      // whether this primeBase has gadgets
      if (allBaseGadgets.find(primeBase) != allBaseGadgets.end()) {
        auto thisBaseHeap = insertBaseHeap(primeBase);
        if (thisBaseHeap != nullptr) {
          allPrimes.insert(primeBase);
          std::set<uint64_t> thisBase;
          thisBase.insert(primeBase);
          std::vector<std::vector<uint64_t>> tmpBaseChains;
          graphToChains<uint64_t>(allBaseMap, thisBase, tmpBaseChains);
          baseChains.insert(baseChains.end(),
                            tmpBaseChains.begin(),
                            tmpBaseChains.end());

          if (BanMultithread)
            traverseBaseChains(tmpBaseChains, allBaseGadgets);
          else {
            try {
              auto ans = tp.add(&BaseHeaps::traverseBaseChains,
                                this,
                                tmpBaseChains,
                                allBaseGadgets);
              v.push_back(std::move(ans));
            } catch (const std::exception &e) {
              outs() << e.what() << '\n';
            }
          }
        }
      }
    }
  }

  for (size_t i = 0; i < v.size(); ++i) {
    std::lock_guard<std::mutex> lg(mtx);
    v[i].get();
    // outs() << v[i].get() << '\n';
  }

  // have no precedess and successor nodes
  int i = 0;
  for (auto iter = allBases.begin(); iter != allBases.end(); iter++) {
    uint64_t thisBase = iter->first;
    bool isPrime = iter->second;
    if (isPrime) {
      if (AllBaseHeaps.find(thisBase) == AllBaseHeaps.end()) {
        if (allBaseGadgets.find(thisBase) != allBaseGadgets.end()) {
          auto thisBaseHeap = insertBaseHeap(thisBase);
          if (thisBaseHeap != nullptr) {
            i++;
            auto thisGadgets = allBaseGadgets.find(thisBase);
            auto thisBaseNode = insertBaseGadgets(&*thisBaseHeap,
                                                  &*thisGadgets);
            thisBaseHeap->second.firstBaseNode = thisBaseNode;
            thisBaseHeap->second.isAlone = true;

            std::map<AssignGadge *, GadgetNode> *thisGadgetsMap = &(
              thisBaseNode->second.gadgetsMap);
            std::set<std::pair<AssignGadge *const, GadgetNode> *>
              thisAllGadgets;
            std::set<std::pair<AssignGadge *const, GadgetNode> *>
              thisLoopGadgets;
            std::set<std::pair<AssignGadge *const, GadgetNode> *>
              thisNotLoopGadgets;

            bool isDivision = loopGadgetsDivision(thisGadgetsMap,
                                                  thisAllGadgets,
                                                  thisLoopGadgets,
                                                  thisNotLoopGadgets);

            thisBaseNode->second.isDivision = isDivision;
            thisBaseNode->second.loopGadgets = thisLoopGadgets;
            thisBaseNode->second.notLoopGadgets = thisNotLoopGadgets;
          }
        }
      }
    }
  }
  // convert allBaseMap into allBaseChains
  // Easy to store with map when traversing
  // using chain is eay to cluster,easy to store into AllBaseHeaps

  // graphToChains<uint64_t>(allBaseMap, allPrimes, baseChains);
}

bool BaseHeaps::loopGadgetsDivision(
  std::map<AssignGadge *, GadgetNode> *gadgetsMap,
  std::set<std::pair<AssignGadge *const, GadgetNode> *> &preAllGadgets,
  std::set<std::pair<AssignGadge *const, GadgetNode> *> &loopGadgets,
  std::set<std::pair<AssignGadge *const, GadgetNode> *> &notLoopGadgets) {
  bool isLoop = false;
  bool isNotLoop = false;
  for (auto iter = gadgetsMap->begin(); iter != gadgetsMap->end(); iter++) {
    AssignGadge *gadget = iter->first;
    std::pair<AssignGadge *const, GadgetNode> *thisGadgetNode = &*iter;
    preAllGadgets.insert(thisGadgetNode);

    if (gadget->isloop) {
      loopGadgets.insert(thisGadgetNode);
      isLoop = true;
    } else {
      notLoopGadgets.insert(thisGadgetNode);
      isNotLoop = true;
    }
  }
  return isLoop & isNotLoop;
}

// inpu new <base,AssignGadge>
//
void BaseHeaps::findUnexploredBases() {
  // find all unexplored bases
  for (auto iter = AllBaseHeaps.begin(); iter != AllBaseHeaps.end(); iter++) {
    uint64_t thisBase = iter->first;
    BaseHeap *thisBaseHeap = &(iter->second);

    findRelatedBases(thisBase, thisBaseHeap);

    // generate gadget chain
    // generateGadgetsChain(thisBaseHeap);
  }
}

// classfy base
void BaseHeaps::findRelatedBases(uint64_t thisBase, BaseHeap *thisBaseHeap) {
  uint64_t baseAddr = (AllUnexploreGlobalAddr.find(thisBase))->second;
  std::vector<uint64_t> nextAddresses;
  theCFGWithNext.findNextAddressesSequence(baseAddr, nextAddresses, 1);

  std::map<uint64_t, std::set<uint64_t>> mergeAddresses;
  for (auto iter = AllUnexploreGlobalAddr.begin();
       iter != AllUnexploreGlobalAddr.end();
       iter++) {
    std::set<uint64_t> unexploreNextAddresses;
    uint64_t unexploreBase = iter->first;
    uint64_t unexploreBaseAddr = iter->second;
    theCFGWithNext.findNextAddresses(unexploreBaseAddr,
                                     unexploreNextAddresses,
                                     10);

    for (auto iter1 = nextAddresses.begin(); iter1 != nextAddresses.end();
         iter1++) {
      if (unexploreNextAddresses.find(*iter1) != unexploreNextAddresses.end()) {
        uint64_t mergeAddr = *iter1;
        std::set<uint64_t> nullBases;
        auto ret = mergeAddresses.insert({ mergeAddr, nullBases });
        ret.first->second.insert(unexploreBase);

        break;
      }
    }
  }

  auto gadgetsMap = thisBaseHeap->firstBaseNode->second.gadgetsMap;
  for (auto iter = gadgetsMap.begin(); iter != gadgetsMap.end(); iter++) {
    uint64_t gadgetAddr = iter->first->block_addr;
    std::vector<uint64_t> gadgetNextAddresses;
    theCFGWithNext.findNextAddressesSequence(gadgetAddr,
                                             gadgetNextAddresses,
                                             0x7FFFFFFF);

    for (auto iter1 = gadgetNextAddresses.begin();
         iter1 != gadgetNextAddresses.end();
         iter1++) {
      uint64_t gadgetNextAddr = *iter1;
      auto mergeNextAddr = mergeAddresses.find(gadgetNextAddr);
      if (mergeNextAddr != mergeAddresses.end()) {
        std::set<uint64_t> bases = mergeNextAddr->second;
        thisBaseHeap->relatedUnexploredBases.insert(bases.begin(), bases.end());
      }
    }
  }

  // theCFG.findRelatedAddresses(mergeAddrs, nextAddresses);

  // int flag = theCFG.getAddressOrder(baseAddr, unexploredAddr);
  // if (flag == 0)
  /*mergeAddresses = theCFG.findMergeAddress(baseAddr, unexploredAddr);
    std::map<uint64_t,uint64_t> unexploreAddrs;
  for(auto iter1 = AllUnexploreGlobalAddr.begin(); iter1 !=
  AllUnexploreGlobalAddr.end(); iter1++)
  {
    uint64_t unexploreBase = (&*iter1)->first;
    if (AllBaseHeaps.find(unexploreBase) != AllBaseHeaps.end())
      continue;
    uint64_t unexploreAddr = (&*iter1)->second;
    unexploreAddrs.insert({unexploreBase, unexploreAddr});
  }
  if (mergeAddresses.size() != 0)
  {
    std::map<AssignGadge *, GadgetNode> gadgetsMap;
    gadgetsMap = firstBaseNode->second.gadgetsMap;
    for (auto iter = mergeAddresses.begin(); iter != mergeAddresses.end();
  iter++)
    {
      uint64_t mergeAddr = *iter;
      for (auto iter1 = gadgetsMap.begin(); iter1 != gadgetsMap.end(); iter1++)
      {
        AssignGadge * gadget = iter1->first;
        uint64_t gadgetAddr = gadget->block_addr;
        int flag = theCFG.getAddressOrder(mergeAddr, gadgetAddr);
        if (flag == 1)
        {
          ret = true;
          break;
        }
      }
    }
  }

  return ret;*/
}

// generate gadgets chains
void BaseHeaps::generateGadgetsChain(BaseHeap *baseHeap) {
  std::pair<uint64_t const, BaseNode> *firstBaseNode;
  firstBaseNode = baseHeap->firstBaseNode;

  std::map<AssignGadge *, nestedNode<AssignGadge *>> allGadgetMap;
  std::set<std::pair<AssignGadge *const, GadgetNode> *>
    allGadgets = baseHeap->allGadgets;
  for (auto iter = allGadgets.begin(); iter != allGadgets.end(); ++iter) {
    std::pair<AssignGadge *const, GadgetNode> *thisGadget = *iter;
    std::set<std::pair<AssignGadge *const, GadgetNode> *>
      nextGadgetNodes = thisGadget->second.nextGadgetNodes;
    if (nextGadgetNodes.size() > 0) {
      nestedNode<AssignGadge *> nullNode;
      auto ret1 = allGadgetMap.insert({ thisGadget->first, nullNode });

      for (auto iter1 = nextGadgetNodes.begin(); iter1 != nextGadgetNodes.end();
           iter1++) {
        std::pair<AssignGadge *const, GadgetNode> *nextGadget = *iter1;
        auto ret2 = allGadgetMap.insert({ nextGadget->first, nullNode });
        ret1.first->second.nextNestedNodes.insert(&*(ret2.first));
        ret2.first->second.preNestedNodes.insert(&*(ret1.first));
      }
    }
  }

  std::set<AssignGadge *> allPrimeGadgets;
  // put all the firstBaseNode's gadgets
  std::map<AssignGadge *, GadgetNode> gadgetsMap = firstBaseNode->second
                                                     .gadgetsMap;
  for (auto iter = gadgetsMap.begin(); iter != gadgetsMap.end(); iter++) {
    if (allGadgetMap.find(iter->first) != allGadgetMap.end())
      allPrimeGadgets.insert(iter->first);
  }

  std::vector<std::vector<AssignGadge *>> gadgetChains;
  graphToChains<AssignGadge *>(allGadgetMap, allPrimeGadgets, gadgetChains);

  baseHeap->gadgetChains = gadgetChains;

  // put all the firstBaseNode's gadgets
  /* std::map<AssignGadge *, GadgetNode> gadgetsMap =
   firstBaseNode->second.gadgetsMap; for (auto iter = gadgetsMap.begin(); iter
   != gadgetsMap.end(); iter++)
   {
     std::pair<AssignGadge * const,GadgetNode> * gadgetPair;
     gadgetPair = &*iter;

     //put the gadgetNode into waitingNodes
     waitingGadgetPairs.push(gadgetPair);
     //allGadgetPairs.insert(gadgetPair);
   }

   while (!waitingGadgetPairs.empty())
   {
     std::pair<AssignGadge * const,GadgetNode> * thisGadgetPair;
     thisGadgetPair = waitingGadgetPairs.top();
     waitingGadgetPairs.pop();

     if (visitedGadgetPairs.size() != 0)
     {
       std::pair<AssignGadge * const,GadgetNode> * tailGadgetPair =
   visitedGadgetPairs.back(); auto tailNext =
   tailGadgetPair->second.nextGadgetNodes; while ((tailNext.find(thisGadgetPair)
   == tailNext.end()))
       {
         visitedGadgetPairs.pop_back();
         if (visitedGadgetPairs.size() != 0)
         {
           tailGadgetPair = visitedGadgetPairs.back();
           tailNext = tailGadgetPair->second.nextGadgetNodes;
         }else
           break;
       }
     }
     visitedGadgetPairs.push_back(thisGadgetPair);

     //put next gadget nodes
     std::set<std::pair<AssignGadge * const,GadgetNode> *> nextGadgetPairs;
     nextGadgetPairs = thisGadgetPair->second.nextGadgetNodes;
     for (auto iter = nextGadgetPairs.begin(); iter != nextGadgetPairs.end();
   iter++)
     {
       std::pair<AssignGadge * const,GadgetNode> * nextGadgetPair;
       nextGadgetPair = *iter;
       //if (allGadgetNodes.find(nextGadgetNode) == allGadgetNodes.end())
       //{
       waitingGadgetPairs.push(nextGadgetPair);
       //allGadgetNodes.insert(nextGadgetNode);
       //}
     }
     if ((nextGadgetPairs.size() == 0) && (visitedGadgetPairs.size() > 1))
     {
       std::queue<AssignGadge *>  gadgetChain;
       for (auto iter = visitedGadgetPairs.begin(); iter !=
   visitedGadgetPairs.end(); iter++)
         {
           AssignGadge * gadget = (*iter)->first;
           gadgetChain.push(gadget);
         }
         baseHeap->gadgetChains.push_back(gadgetChain);
     }
   }*/
}

// connect gadgets in different bases of the same baseHeap
std::pair<uint64_t,
          std::vector<std::pair<
            std::set<std::pair<AssignGadge *const, BaseHeaps::GadgetNode> *> *,
            std::pair<AssignGadge *const, BaseHeaps::GadgetNode> *>>>
BaseHeaps::gadgetConnection(
  std::set<std::pair<AssignGadge *const, GadgetNode> *> &thisGadgetsMap,
  std::set<std::pair<AssignGadge *const, GadgetNode> *> &nextGadgetsMap,
  bool isSameBase,
  uint64_t primeBase,
  int number,
  bool preDivision) {
  std::vector<std::pair<std::set<std::pair<AssignGadge *const, GadgetNode> *> *,
                        std::pair<AssignGadge *const, GadgetNode> *>>
    gadgetPairs;
  for (auto iter = thisGadgetsMap.begin(); iter != thisGadgetsMap.end();
       iter++) {
    std::pair<AssignGadge *const, GadgetNode> *thisGadget = *iter;
    uint64_t thisAddr = thisGadget->first->block_addr;

    std::vector<uint64_t> nextAddresses;
    theCFG.findNextAddressesSequence(thisAddr, nextAddresses, 0x7fffffff);
    std::set<uint64_t> addresses;
    for (auto iter = nextAddresses.begin(); iter != nextAddresses.end(); iter++)
      addresses.insert(*iter);

    std::set<std::pair<AssignGadge *const, GadgetNode> *> *nextGadgetNodes;
    nextGadgetNodes = &(thisGadget->second.nextGadgetNodes);

    if (thisAddr != 0) {
      for (auto iter1 = nextGadgetsMap.begin(); iter1 != nextGadgetsMap.end();
           iter1++) {
        std::pair<AssignGadge *const, GadgetNode> *nextGadgetMap;
        nextGadgetMap = *iter1;
        uint64_t nextAddr = nextGadgetMap->first->block_addr;
        if (nextAddr != 0) {
          // find the relationship of thisGadget and nextGadget
          int flag = 0;
          if (isSameBase)
            flag = theCFG.getAddressOrder(thisAddr, nextAddr);
          else
            flag = theCFG.isAddressPrecedent(addresses, nextAddr);
          if (flag > 0) {
            if (BanMultithread) {
              nextGadgetNodes->insert(nextGadgetMap);
              nextGadgetMap->second.preGadgetNodes.insert(thisGadget);
            } else {
              gadgetPairs.push_back({ nextGadgetNodes, nextGadgetMap });
              gadgetPairs.push_back(
                { &(nextGadgetMap->second.preGadgetNodes), thisGadget });
            }
          }
          // 0: addr and nextAddr are not connected in cfgMap
          // 1: addr is before nextAddrin cfgMap
          // 2: addr is after nextAddr in cfgMap
          /*flag = theCFG.getAddressOrder(thisAddr, nextAddr);
          //if thisGadget is before nextGadget in cfg,put them into the
          gadgetsMap if (flag == 1)
          {
            nextGadgetNodes->insert(nextGadgetMap);
            isConnected = true;
          }
          if (flag == 2 && isSameBase)
          {
            nextGadgetNodes->insert(nextGadgetMap);
            isConnected = true;
          }*/
        }
      }
    }
  }

  return { primeBase, gadgetPairs };

  /*for (auto iter = thisGadgetsMap->begin(); iter != thisGadgetsMap->end();
  iter++)
  {
    uint64_t thisAddr = findAddress((&*iter)->first);
    std::set<std::pair<AssignGadge * const,GadgetNode> * > * nextGadgetNodes;
    nextGadgetNodes = &((&*iter)->second.nextGadgetNodes);

    if (thisAddr != 0)
    {
      std::map<uint64_t, std::pair<AssignGadge * const,GadgetNode> *>
  nextGadgetsAddr; std::map<uint64_t, bool> nextAddrs; for (auto iter1 =
  nextGadgetsMap->begin(); iter1 != nextGadgetsMap->end(); iter1++)
      {
        std::pair<AssignGadge * const,GadgetNode> * nextGadgetMap;
        nextGadgetMap = &*iter1;
        uint64_t nextAddr = findAddress(nextGadgetMap->first);
        if (nextAddr != 0)
        {
          nextGadgetsAddr.insert({nextAddr, nextGadgetMap});
          nextAddrs.insert({nextAddr, false});
        }
      }

      theCFG.getAddressesOrder(thisAddr, nextAddrs);

      for (auto iter1 = nextAddrs.begin(); iter1 != nextAddrs.end(); iter1++)
      {
        uint64_t addr = iter1->first;
        bool relationship = iter1->second;
        if (relationship)
        {
          std::pair<AssignGadge * const,GadgetNode> * gadgetsMap;
          gadgetsMap = (nextGadgetsAddr.find(addr))->second;
          nextGadgetNodes->insert(gadgetsMap);
        }
      }

    }
  }*/
}

void BaseHeaps::getUsedGadgets(
  std::vector<std::pair<AssignGadge *const, GadgetNode> *> &allGadgets,
  std::vector<AssignGadge *> &usedGadgets) {
  for (auto iter = allGadgets.begin(); iter != allGadgets.end(); iter++) {
    auto nextGadgetNodes = (*iter)->second.nextGadgetNodes;
    auto preGadgetNodes = (*iter)->second.preGadgetNodes;
    if (nextGadgetNodes.size() > 0 || preGadgetNodes.size() > 0) {
      AssignGadge *gadget = (*iter)->first;
      usedGadgets.push_back(gadget);
    }
  }
}

void BaseHeaps::getAllGadgetChains(
  BaseHeap *thisBaseHeap,
  std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
    &gadgetChains) {
  std::map<std::vector<uint64_t>,
           std::vector<std::pair<
             uint64_t,
             std::pair<std::set<AssignGadge *>, std::set<AssignGadge *>>>>>
    waitingGadgetChains;
  std::map<std::pair<uint64_t, uint64_t>,
           std::vector<std::pair<std::vector<uint64_t>, int>>>
    allTransformations;
  auto thisBaseChains = thisBaseHeap->baseChains;
  for (size_t i = 0; i < thisBaseChains.size(); i++) {
    std::vector<uint64_t> aBaseChain = thisBaseChains[i];
    if (aBaseChain.size() > 1) {
      std::vector<
        std::pair<uint64_t,
                  std::pair<std::set<AssignGadge *>, std::set<AssignGadge *>>>>
        thisChain;
      std::set<AssignGadge *> nullGadgets;
      std::vector<std::pair<std::vector<uint64_t>, int>> nullIndex;

      thisChain.push_back({ aBaseChain[0], { nullGadgets, nullGadgets } });
      auto ret = thisBaseHeap->basesInHeap.find(aBaseChain[0]);
      if (ret->second.isDivision) {
        auto ret = allTransformations.insert(
          { { aBaseChain[0], aBaseChain[0] }, nullIndex });
        ret.first->second.push_back({ aBaseChain, 0 });
      }

      for (size_t j = 1; j < aBaseChain.size(); j++) {
        thisChain.push_back({ aBaseChain[j], { nullGadgets, nullGadgets } });
        auto ret1 = allTransformations.insert(
          { { aBaseChain[j - 1], aBaseChain[j] }, nullIndex });
        ret1.first->second.push_back({ aBaseChain, j });

        auto ret2 = thisBaseHeap->basesInHeap.find(aBaseChain[j]);
        if (ret2->second.isDivision) {
          auto ret3 = allTransformations.insert(
            { { aBaseChain[j], aBaseChain[j] }, nullIndex });
          ret3.first->second.push_back({ aBaseChain, j });
        }
      }
      waitingGadgetChains.insert({ aBaseChain, thisChain });
    }
  }

  auto firstBaseNode = thisBaseHeap->firstBaseNode;
  std::queue<std::pair<uint64_t const, BaseNode> *> nextBaseNodes;
  std::set<std::pair<uint64_t const, BaseNode> *> allBaseNodes;
  nextBaseNodes.push(firstBaseNode);
  allBaseNodes.insert(firstBaseNode);

  while (nextBaseNodes.size() > 0) {
    auto thisBaseNode = nextBaseNodes.front();
    nextBaseNodes.pop();

    auto thisGadgetsMap = thisBaseNode->second.gadgetsMap;
    for (auto iter = thisGadgetsMap.begin(); iter != thisGadgetsMap.end();
         iter++) {
      AssignGadge *thisGadget = iter->first;
      uint64_t thisBase = thisGadget->global_addr;
      bool thisIsLoop = thisGadget->isloop;
      auto nextGadgetNodes = iter->second.nextGadgetNodes;
      for (auto iter1 = nextGadgetNodes.begin(); iter1 != nextGadgetNodes.end();
           iter1++) {
        AssignGadge *nextGadget = (*iter1)->first;
        uint64_t nextBase = nextGadget->global_addr;
        bool nextIsLoop = nextGadget->isloop;
        auto ret = allTransformations.find({ thisBase, nextBase });
        std::vector<std::pair<std::vector<uint64_t>, int>> indexs = ret->second;
        for (auto iter2 = indexs.begin(); iter2 != indexs.end(); iter2++) {
          std::vector<uint64_t> thisBaseChain = (*iter2).first;
          std::vector<std::pair<
            uint64_t,
            std::pair<std::set<AssignGadge *>, std::set<AssignGadge *>>>>
            *thisGadgets;
          thisGadgets = &(waitingGadgetChains.find(thisBaseChain)->second);
          if (thisBase == thisBaseChain[0]) {
            if (thisIsLoop)
              thisGadgets->begin()->second.first.insert(thisGadget);
            else
              thisGadgets->begin()->second.second.insert(thisGadget);
          }

          int index = (*iter2).second;
          if (thisBase == nextBase) {
            if (thisIsLoop == true && nextIsLoop == false) {
              auto thisBaseGadgets = &((thisGadgets->begin() + index)->second);
              auto ret4 = thisBaseGadgets->first.find(thisGadget);
              if (ret4 != thisBaseGadgets->first.end())
                thisBaseGadgets->second.insert(nextGadget);
            } else
              outs() << "error1:sameBase: " << thisBase
                     << " thisIsLoop:" << thisIsLoop
                     << " nextIsLoop:" << nextIsLoop << "\n";
          } else if (thisBase == thisBaseChain[index - 1]
                     && nextBase == thisBaseChain[index]) {
            auto thisBaseGadgets = &(
              (thisGadgets->begin() + index - 1)->second);
            auto nextBaseGadgets = &((thisGadgets->begin() + index)->second);
            bool isThisFind = false;
            if (thisIsLoop) {
              auto ret4 = thisBaseGadgets->first.find(thisGadget);
              if (ret4 != thisBaseGadgets->first.end())
                isThisFind = true;
            } else {
              auto ret4 = thisBaseGadgets->second.find(thisGadget);
              if (ret4 != thisBaseGadgets->second.end())
                isThisFind = true;
            }

            if (isThisFind && nextIsLoop)
              nextBaseGadgets->first.insert(nextGadget);
            else if (isThisFind && !nextIsLoop)
              nextBaseGadgets->second.insert(nextGadget);
          } else
            outs() << "error3:thisBase:" << thisBase << " nextBase:" << nextBase
                   << "\n";
        }
      }
    }

    auto nextBaseNode = thisBaseNode->second.nextBaseNodes;
    for (auto iter = nextBaseNode.begin(); iter != nextBaseNode.end(); iter++) {
      auto ret = allBaseNodes.insert(*iter);
      if (ret.second)
        nextBaseNodes.push(*iter);
    }
  }

  std::set<std::vector<uint64_t>> finalBaseChains;
  for (auto iter = waitingGadgetChains.begin();
       iter != waitingGadgetChains.end();
       iter++) {
    std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>> gadgets;
    auto gadgetsChain = iter->second;
    bool preIsDivision = false;
    int preLoopSize = 0;
    for (auto iter1 = gadgetsChain.begin(); iter1 != gadgetsChain.end();
         iter1++) {
      uint64_t base = iter1->first;
      bool isPushed = false;
      bool isDivision = thisBaseHeap->basesInHeap.find(base)->second.isDivision;
      auto loopGadgets = iter1->second.first;
      auto notLoopGadgets = iter1->second.second;
      if (loopGadgets.size() > 0) {
        std::vector<AssignGadge *> allGadgets;
        for (auto iter2 = loopGadgets.begin(); iter2 != loopGadgets.end();
             iter2++)
          allGadgets.push_back(*iter2);
        gadgets.push_back({ base, allGadgets });
        isPushed = true;
      }
      if (notLoopGadgets.size() > 0 && !(preIsDivision && preLoopSize == 0)) {
        std::vector<AssignGadge *> allGadgets;
        for (auto iter2 = notLoopGadgets.begin(); iter2 != notLoopGadgets.end();
             iter2++)
          allGadgets.push_back(*iter2);
        gadgets.push_back({ base, allGadgets });
        isPushed = true;
      }

      preIsDivision = isDivision;
      preLoopSize = loopGadgets.size();
      if (!isPushed)
        break;
    }

    std::vector<uint64_t> finalBaseChain;
    for (auto iter1 = gadgets.begin(); iter1 != gadgets.end(); iter1++)
      finalBaseChain.push_back(iter1->first);

    auto ret = finalBaseChains.insert(finalBaseChain);
    if (gadgets.size() > 0 && ret.second)
      gadgetChains.push_back(gadgets);
  }
  /*      uint64_t secondBaseains.insert({secondBase, {nullBases,
    nullGadgetChains}}); if(aBaseChain.size() >2)
        {
          for (auto iter1 = aBaseChain.begin() + 2; iter1 != aBaseChain.end();
    iter1++)
          {
            ret.first->second.first.push(*iter1);
          }
        }
      }

    }



    std::pair<uint64_t const, BaseNode> * firstBaseNode =
    thisBaseHeap->firstBaseNode;

    std::set<std::pair<uint64_t const, BaseNode> *> allBaseNodes;
    std::queue<std::pair<uint64_t const,BaseNode>*> nextBaseNodes;
    std::pair<uint64_t const,BaseNode> * nextBaseNode;

    //Depth-first traversal
    nextBaseNodes.push(firstBaseNode);
    nextBaseNodes.push(nullptr);
    allBaseNodes.insert(firstBaseNode);

    std::vector<std::pair<AssignGadge * const, GadgetNode> *> loopGadgets;
    std::vector<std::pair<AssignGadge * const, GadgetNode> *> notLoopGadgets;
    while((nextBaseNodes.size() != 0))
    {
      nextBaseNode = nextBaseNodes.front();
      nextBaseNodes.pop();

      if (nextBaseNode == nullptr)
      {
        int gadgetsSize = 0;
        if (loopGadgets.size() > 0)
        {
          std::vector<AssignGadge *> gadgets;
          getUsedGadgets(loopGadgets, gadgets);
          if (gadgets.size() >0)
          {
            gadgetChains.push_back(gadgets);
            gadgetsSize += gadgetChains.size();
          }
        }

        if (notLoopGadgets.size() > 0)
        {
          std::vector<AssignGadge *> gadgets;
          getUsedGadgets(notLoopGadgets, gadgets);
          if (gadgets.size() >0)
          {
            gadgetChains.push_back(gadgets);
            gadgetsSize += gadgetChains.size();
          }
        }

        if (gadgetsSize == 0 || nextBaseNodes.size() == 0)
          break;

        std::vector<std::pair<AssignGadge * const, GadgetNode>
    *>().swap(loopGadgets); std::vector<std::pair<AssignGadge * const,
    GadgetNode> *>().swap(notLoopGadgets); nextBaseNodes.push(nullptr);
        continue;
      }

      auto nextLoopGadgets = nextBaseNode->second.loopGadgets;
      auto nextNotLoopGadgets = nextBaseNode->second.notLoopGadgets;
      if (nextBaseNode->second.isDivision)
      {
        loopGadgets.insert(loopGadgets.end(), nextLoopGadgets.begin(),
    nextLoopGadgets.end());
      }
      notLoopGadgets.insert(notLoopGadgets.end(), nextNotLoopGadgets.begin(),
    nextNotLoopGadgets.end());

      auto nextNodes = nextBaseNode->second.nextBaseNodes;
      for (auto iter = nextNodes.begin(); iter != nextNodes.end(); ++iter)
      {
        nextBaseNodes.push(*iter);
      }
    }*/
}

void BaseHeaps::getAllGadgets(
  BaseHeap *thisBaseHeap,
  std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
    &allGadgets) {
  auto thisBaseChains = thisBaseHeap->baseChains;
  for (auto iter = thisBaseChains.begin(); iter != thisBaseChains.end();
       iter++) {
    std::vector<uint64_t> thisBaseChain = *iter;
    std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>> oneGadgets;
    for (auto iter1 = thisBaseChain.begin(); iter1 != thisBaseChain.end();
         iter1++) {
      uint64_t thisBase = *iter1;
      auto thisBaseMap = thisBaseHeap->basesInHeap.find(thisBase);
      if (thisBaseMap->second.isDivision) {
        std::vector<AssignGadge *> gadgets;
        auto loopGadgets = thisBaseMap->second.loopGadgets;
        for (auto iter2 = loopGadgets.begin(); iter2 != loopGadgets.end();
             iter2++)
          gadgets.push_back((*iter2)->first);
        oneGadgets.push_back({ thisBase, gadgets });
      }
      std::vector<AssignGadge *> gadgets;
      auto notLoopGadgets = thisBaseMap->second.notLoopGadgets;
      for (auto iter2 = notLoopGadgets.begin(); iter2 != notLoopGadgets.end();
           iter2++)
        gadgets.push_back((*iter2)->first);
      oneGadgets.push_back({ thisBase, gadgets });
    }
    allGadgets.push_back(oneGadgets);
  }
}

std::vector<JumpTargetManager::ABaseHeap> BaseHeaps::getBaseHeaps() {
  std::vector<JumpTargetManager::ABaseHeap> finalBaseHeaps;
  for (auto iter = AllBaseHeaps.begin(); iter != AllBaseHeaps.end(); iter++) {
    uint64_t thisBase = iter->first;
    JumpTargetManager::ABaseHeap aBaseHeap;
    aBaseHeap.relatedUnexploredBases = iter->second.relatedUnexploredBases;
    aBaseHeap.relatedUnexploredBases.insert(thisBase);
    if (!iter->second.isAlone) {
      getAllGadgetChains(&(iter->second), aBaseHeap.gadgetChains);
      getAllGadgets(&(iter->second), aBaseHeap.allGadgets);
    } else {
      std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>
        thisAllGadgets;
      auto thisBaseNode = iter->second.firstBaseNode;
      if (thisBaseNode->second.isDivision) {
        std::vector<AssignGadge *> gadgets;
        auto loopGadgets = thisBaseNode->second.loopGadgets;
        for (auto iter2 = loopGadgets.begin(); iter2 != loopGadgets.end();
             iter2++)
          gadgets.push_back((*iter2)->first);
        thisAllGadgets.push_back({ thisBase, gadgets });
      }
      std::vector<AssignGadge *> gadgets;
      auto notLoopGadgets = thisBaseNode->second.notLoopGadgets;
      for (auto iter2 = notLoopGadgets.begin(); iter2 != notLoopGadgets.end();
           iter2++)
        gadgets.push_back((*iter2)->first);
      thisAllGadgets.push_back({ thisBase, gadgets });

      aBaseHeap.gadgetChains.push_back(thisAllGadgets);
      aBaseHeap.allGadgets.push_back(thisAllGadgets);
    }
    finalBaseHeaps.push_back(aBaseHeap);
  }

  return finalBaseHeaps;
}

void BaseHeaps::putGadgets(
  std::set<std::pair<BaseHeaps::AssignGadge *const, BaseHeaps::GadgetNode> *>
    &allGadgets,
  std::vector<AssignGadge *> &finalGadgets) {
  for (auto iter = allGadgets.begin(); iter != allGadgets.end(); iter++) {
    std::pair<BaseHeaps::AssignGadge *const, BaseHeaps::GadgetNode>
      *thisGadget = *iter;
    if (thisGadget->second.nextGadgetNodes.size() > 0) {
      AssignGadge *finalGadget = (*iter)->first;
      finalGadgets.push_back(finalGadget);
    }
  }
}

void JumpTargetManager::testFunction() {
  CFGMap theCFG(SrcToDests, textStartAddr, textEndAddr);
  /* //insert new nodes into theCFG
  theCFG.insertNew(4222263, 4221308);
  theCFG.insertNew(4222263, 4221308);
  theCFG.insertNew(4220410, 4219375);*/
  theCFG.printCFGMap();
  CFGMap theCFGWithNext(SrcToDestsWithNext, textStartAddr, textEndAddr);

  BaseHeaps baseHeaps(theCFG,
                      theCFGWithNext,
                      assign_gadge,
                      AllUnexploreGlobalAddr);
  std::vector<ABaseHeap> allBaseHeaps;
  allBaseHeaps = baseHeaps.getBaseHeaps();

  for (auto index : allBaseHeaps) {
    if (!MPCP) {
      for (auto base : index.relatedUnexploredBases) {
        for (auto group : index.gadgetChains)
          CodePointerharvestInOptmChains(base, group);
      }
    }

    if (MPCP)
      MultiProcessCodePointerharvest(index);
  }

  //  for(auto index : allBaseHeaps){
  //    for(auto base : index.second.relatedUnexploredBases){
  //      for(auto chain : index.second.gadgetChains){
  //        CodePointerharvestInOptmChains(base,chain);
  //      }
  //    }
  //  }
}

void JumpTargetManager::MultiProcessCodePointerharvest(ABaseHeap &abheap) {
  using TYPE = uint64_t;
  std::vector<TYPE> CONTAINER;
  ABaseHeap ab = abheap;

  CONTAINER.assign(abheap.relatedUnexploredBases.begin(),
                   abheap.relatedUnexploredBases.end());
  errs() << "processes: " << CONTAINER.size() << "\n";

  size_t N = ProcessNums;
  auto begin = CONTAINER.begin();
  auto size = CONTAINER.size();
  auto End = CONTAINER.end();

  if (CONTAINER.size() > ProcessNums) {
    N = ProcessNums;
  } else
    N = CONTAINER.size();

  pid_t pid[N];
  char *stack;
  stack = (char *) malloc(STACK_SIZE * N);
  if (stack == NULL) {
    errs() << "malloc failed"
           << "\n";
    exit(-1);
  }

  for (size_t i = 1; i <= N; i++) {
    std::vector<TYPE> process;
    size_t sbegin = ((size - size % N) / N) * (i - 1);
    size_t send = ((size - size % N) / N) * i;
    process.insert(process.begin(), begin + sbegin, begin + send);
    if (i == N) {
      process.clear();
      process.insert(process.begin(), begin + sbegin, End);
    }

    uint64_t ARGS[3];
    ARGS[0] = (uint64_t)(&process);
    ARGS[1] = (uint64_t)(this);
    ARGS[2] = (uint64_t)(&ab);
    pid[i - 1] = clone(ChainsProcess,
                       stack + i * STACK_SIZE,
                       SIGCHLD,
                       (void *) ARGS);
    if (pid[i - 1] == -1) {
      errs() << "clone failed"
             << "\n";
      exit(-1);
    }
  }

  auto n = N;
  while (n > 0) {
    wait(NULL);
    errs() << "process ends \n";
    n--;
  }
  free(stack);
}

int JumpTargetManager::ChainsProcess(void *Buf) {
  uint64_t *p = (uint64_t *) Buf;
  void *arg1 = (void *) (*p);
  void *arg2 = (void *) (*(p + 1));
  void *arg3 = (void *) (*(p + 2));

  std::vector<uint64_t> &bases = *reinterpret_cast<std::vector<uint64_t> *>(
    arg1);
  JumpTargetManager *jtm = (JumpTargetManager *) arg2;
  ABaseHeap *abheap = (ABaseHeap *) arg3;

  errs() << "process: " << bases.size() << "\n\n";

  for (auto base : bases) {

    // for(auto group : abheap->gadgetChains)
    //  jtm->CodePointerharvestInOptmChains(base,group);

    jtm->MultiProcessGroupChains(base, abheap->gadgetChains);
  }

  return 0;
}

void JumpTargetManager::MultiProcessGroupChains(uint64_t base,
                                                GADGETCHAINS &gadgetChains) {
  using TYPE1 = GADGETCHAINS;
  TYPE1 CONTAINER;
  CONTAINER = gadgetChains;

  errs() << "chains processes: " << CONTAINER.size() << "\n";
  if (CONTAINER.empty())
    return;

  size_t N = ProcessNums;
  auto begin = CONTAINER.begin();
  auto size = CONTAINER.size();
  auto End = CONTAINER.end();

  if (CONTAINER.size() > ProcessNums) {
    N = ProcessNums;
  } else
    N = CONTAINER.size();

  pid_t pid[N];
  char *stack;
  stack = (char *) malloc(STACK_SIZE * N);
  if (stack == NULL) {
    errs() << "malloc failed"
           << "\n";
    exit(-1);
  }

  for (size_t i = 1; i <= N; i++) {
    TYPE1 process;
    size_t sbegin = ((size - size % N) / N) * (i - 1);
    size_t send = ((size - size % N) / N) * i;
    process.insert(process.begin(), begin + sbegin, begin + send);
    if (i == N) {
      process.clear();
      process.insert(process.begin(), begin + sbegin, End);
    }

    uint64_t ARGS[3];
    ARGS[0] = (uint64_t)(&process);
    ARGS[1] = (uint64_t)(this);
    ARGS[2] = base;
    pid[i - 1] = clone(GadgetChainsProcess,
                       stack + i * STACK_SIZE,
                       SIGCHLD,
                       (void *) ARGS);
    if (pid[i - 1] == -1) {
      errs() << "clone failed"
             << "\n";
      exit(-1);
    }
  }

  auto n = N;
  while (n > 0) {
    wait(NULL);
    errs() << "chains process ends \n";
    n--;
  }
  free(stack);
}

int JumpTargetManager::GadgetChainsProcess(void *Buf) {
  uint64_t *p = (uint64_t *) Buf;
  void *arg1 = (void *) (*p);
  void *arg2 = (void *) (*(p + 1));
  uint64_t arg3 = *(p + 2);

  GADGETCHAINS &GadgetChains = *reinterpret_cast<GADGETCHAINS *>(arg1);
  JumpTargetManager *jtm = (JumpTargetManager *) arg2;
  uint64_t base = arg3;

  errs() << "chains process: " << GadgetChains.size() << "\n\n";

  for (auto group : GadgetChains)
    jtm->CodePointerharvestInOptmChains(base, group);

  return 0;
}

void JumpTargetManager::CodePointerharvestInOptmChains(
  uint64_t reserve,
  std::vector<AssignGadge *> chain) {
  AllGloCandidataAddr.clear();
  // Run th chain.
  runChain(reserve, chain);

  // Handle *(base+index)+offset
  // e.g., add 0x8724e0(%rbp), %rbx
  //       jne ...
  auto G = chain.front();
  auto gadget = G->operation_block ? G->operation_block : G->static_addr_block;
  auto thisAddr = getInstructionPC(&*(gadget->begin()));
  auto current_pc = getInstructionPC(G->global_I);
  auto opt = UndefineOP;

  if (current_pc == thisAddr) {
    auto OPs = getIndexReg(G->global_I);
    if (!OPs.empty() and (OPs.size() > 1)) {
      opt = OPs.front();
    }

    if (G->isloop and opt != UndefineOP) {
      auto base = G->global_addr;
      int n = 0;
      // In the memory space represented by base,
      // we consider that base' (generated by *(base+index)) is stored
      // continuously. We also can handle discontinuous situations in the
      // future. Discontinuous memory: TODO: ...
      while (isGlobalData(base)) {
        base = *((uint64_t *) (G->global_addr + n * 8));
        n++;
      }

      // Iterate index and run gadget chain.
      for (int i = 0; i <= n; i++) {
        // Set reg.
        ptc.regs[opt] = i * 8;
        AllGloCandidataAddr.clear();
        runChain(reserve, chain);
      }
    }
  }
}
void JumpTargetManager::runChain(uint64_t reserve,
                                 std::vector<AssignGadge *> chain) {
  std::set<uint64_t> tmpGlobal;
  std::set<uint64_t> &tmpGlobal1 = tmpGlobal;

  tmpGlobal1.insert(reserve);
  for (auto g : chain) {
    auto gadget = g->static_addr_block;
    bool oper = false;
    if (g->operation_block) {
      gadget = g->operation_block;
      oper = true;
    }
    auto global_I = g->global_I;
    auto op = g->op;
    auto indirect = g->indirect;
    auto isloop = g->isloop;
    runGlobalGadget(gadget, oper, global_I, op, indirect, isloop, tmpGlobal1);
  }
}

// GROUP: std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>
void JumpTargetManager::CodePointerharvestInOptmChains(uint64_t reserve,
                                                       GROUP group) {
  if (group.empty())
    return;

  AllGloCandidataAddr.clear();
  // Run th chain.
  runChain(reserve, group);

  // Handle *(base+index)+offset
  // e.g., add 0x8724e0(%rbp), %rbx
  //       jne ...
  auto Gs = group.front().second;
  for (auto G : Gs) {
    auto gadget = G->operation_block ? G->operation_block :
                                       G->static_addr_block;
    auto thisAddr = getInstructionPC(&*(gadget->begin()));
    auto current_pc = getInstructionPC(G->global_I);
    auto opt = UndefineOP;

    if (current_pc == thisAddr) {
      auto OPs = getIndexReg(G->global_I);
      if (!OPs.empty() and (OPs.size() > 1)) {
        opt = OPs.front();
      }

      if (G->isloop and opt != UndefineOP) {
        auto base = G->global_addr;
        int n = 0;
        // In the memory space represented by base,
        // we consider that base' (generated by *(base+index)) is stored
        // continuously. We also can handle discontinuous situations in the
        // future. Discontinuous memory: TODO: ...
        while (isGlobalData(base)) {
          base = *((uint64_t *) (G->global_addr + n * 8));
          n++;
        }

        // Iterate index and run gadget chain.
        for (int i = 0; i <= n; i++) {
          // Set reg.
          ptc.regs[opt] = i * 8;
          AllGloCandidataAddr.clear();
          runChain(reserve, group);
        }
      }
    }
  }
}

void JumpTargetManager::runChain(uint64_t reserve, GROUP group) {
  std::set<uint64_t> AllSeeds;

  AllSeeds.insert(reserve);
  uint64_t pre_base = 0;
  for (auto level : group) {
    // level : std::pair<uint64_t, std::vector<AssignGadge *>
    std::set<uint64_t> seed;
    seed = AllSeeds;
    // reserve the output of different levels but the same base.
    if (pre_base != level.first)
      AllSeeds.clear();
    pre_base = level.first;

    if (level.second.size() > MAXGADGETSNUM)
      return;
    for (auto g : level.second) {
      // Initial tmpGlobal
      std::set<uint64_t> tmpGlobal;
      tmpGlobal = seed;

      auto gadget = g->static_addr_block;
      bool oper = false;
      if (g->operation_block) {
        gadget = g->operation_block;
        oper = true;
      }
      auto global_I = g->global_I;
      auto op = g->op;
      auto indirect = g->indirect;
      auto isloop = g->isloop;
      runGlobalGadget(gadget, oper, global_I, op, indirect, isloop, tmpGlobal);
      AllSeeds.insert(tmpGlobal.begin(), tmpGlobal.end());
    }
  }
}

void JumpTargetManager::readDebugInfo(std::string OutputPath) {
  ////////////////////////SrcToDests
  auto SrcToDestsPath = OutputPath + ".SrcToDests.csv";
  std::ifstream SrcToDestsFile(SrcToDestsPath);
  std::string line;
  grin_assert(SrcToDestsFile, "Couldn't open the SrcToDests file");
  // read cfg file line by line,every line stores one address and its
  // successors.
  while (getline(SrcToDestsFile, line)) {
    std::istringstream addresses(line);
    std::string address;

    // obtain the source address
    addresses >> address;
    uint64_t source_address = std::strtoull(address.c_str(), NULL, 16);
    std::set<uint64_t> successor_addresses;
    // obtain all the source's successors,and store <source,successor>
    while (addresses >> address) {
      uint64_t successor_address = std::strtoull(address.c_str(), NULL, 16);
      successor_addresses.insert(successor_address);
    }

    SrcToDests.insert({ source_address, successor_addresses });
  }

  SrcToDestsFile.close();

  ////////////////////////SrcToDests
  auto SrcToDestsWithNextPath = OutputPath + ".SrcToDestsWithNext.csv";
  std::ifstream SrcToDestsWithNextFile(SrcToDestsWithNextPath);
  std::string line1;
  grin_assert(SrcToDestsWithNextFile,
              "Couldn't open the SrcToDestsWithNext file");
  // read cfg file line by line,every line stores one address and its
  // successors.
  while (getline(SrcToDestsWithNextFile, line1)) {
    std::istringstream addresses(line1);
    std::string address;

    // obtain the source address
    addresses >> address;
    uint64_t source_address = std::strtoull(address.c_str(), NULL, 16);
    std::set<uint64_t> successor_addresses;
    // obtain all the source's successors,and store <source,successor>
    while (addresses >> address) {
      uint64_t successor_address = std::strtoull(address.c_str(), NULL, 16);
      successor_addresses.insert(successor_address);
    }

    SrcToDestsWithNext.insert({ source_address, successor_addresses });
  }

  SrcToDestsWithNextFile.close();

  /////////////////////////////AllUnexploreGlobalAddr
  auto AllUnexploreGlobalAddrPath = OutputPath + ".AllUnexploreGlobalAddr.csv";
  std::ifstream AllUnexploreGlobalAddrFile(AllUnexploreGlobalAddrPath);
  grin_assert(AllUnexploreGlobalAddrFile,
              "Couldn't open the AllUnexploreGlobalAddr file");
  while (getline(AllUnexploreGlobalAddrFile, line)) {
    std::istringstream addresses(line);
    std::string address;

    // obtain the source address
    addresses >> address;
    uint64_t globalAddr = std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    uint64_t cfgAddr = std::strtoull(address.c_str(), NULL, 16);

    AllUnexploreGlobalAddr.insert({ globalAddr, cfgAddr });
  }

  AllUnexploreGlobalAddrFile.close();

  /////////////////////////////////assign_gadge
  auto assign_gadgePath = OutputPath + ".assign_gadge.csv";
  std::ifstream assign_gadgeFile(assign_gadgePath);
  grin_assert(assign_gadgeFile, "Couldn't open the assign_gadge file");
  while (getline(assign_gadgeFile, line)) {
    std::istringstream addresses(line);
    std::string address;

    addresses >> address;
    uint64_t baseAddr = std::strtoull(address.c_str(), NULL, 16);

    AssignGadge aGadget;
    addresses >> address;
    aGadget.global_addr = std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.pre = std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.global_I = (llvm::Instruction *) std::strtoull(address.c_str(),
                                                           NULL,
                                                           16);
    addresses >> address;
    aGadget.op = (uint32_t) std::strtoull(address.c_str(), NULL, 0);
    addresses >> address;
    aGadget.block_addr = std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.operation_block = (llvm::BasicBlock *)
      std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.static_addr_block = (llvm::BasicBlock *)
      std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.static_global_I = (llvm::Instruction *)
      std::strtoull(address.c_str(), NULL, 16);
    addresses >> address;
    aGadget.static_op = (uint32_t) std::strtoull(address.c_str(), NULL, 0);
    addresses >> address;
    aGadget.indirect = (bool) std::strtoull(address.c_str(), NULL, 0);
    addresses >> address;
    aGadget.isloop = (uint32_t) std::strtoull(address.c_str(), NULL, 0);
    addresses >> address;
    aGadget.end = (bool) std::strtoull(address.c_str(), NULL, 0);

    assign_gadge.push_back({ baseAddr, aGadget });
  }
  assign_gadgeFile.close();
}

void JumpTargetManager::testDebugFunction() {
  CFGMap theCFG(SrcToDests, textStartAddr, textEndAddr);
  /* //insert new nodes into theCFG
  theCFG.insertNew(4222263, 4221308);
  theCFG.insertNew(4222263, 4221308);
  theCFG.insertNew(4220410, 4219375);*/
  // theCFG.printCFGMap();
  CFGMap theCFGWithNext(SrcToDestsWithNext, textStartAddr, textEndAddr);

  BaseHeaps baseHeaps(theCFG,
                      theCFGWithNext,
                      assign_gadge,
                      AllUnexploreGlobalAddr);
  std::vector<ABaseHeap> allBaseHeaps;
  allBaseHeaps = baseHeaps.getBaseHeaps();
  printAllGadgets(allBaseHeaps);
}

void JumpTargetManager::printAllGadgets(std::vector<ABaseHeap> &allBaseHeaps) {
  for (auto iter = allBaseHeaps.begin(); iter != allBaseHeaps.end(); iter++) {
    ABaseHeap thisBaseHeap = *iter;
    outs() << "================================================================"
              "==========\n";

    std::set<uint64_t> relatedUnexploredBases = thisBaseHeap
                                                  .relatedUnexploredBases;
    outs() << "     relatedBases:";
    for (auto iter1 = relatedUnexploredBases.begin();
         iter1 != relatedUnexploredBases.end();
         iter1++) {
      outs() << " " << format_hex(*iter1, 0);
    }
    outs() << "\n";

    std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
      allGadgets = thisBaseHeap.gadgetChains;
    int i = 0;
    for (auto iter1 = allGadgets.begin(); iter1 != allGadgets.end(); iter1++) {
      i++;
      outs() << "     baseChain" << i << ":\n";
      std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>
        baseChain = *iter1;
      for (auto iter2 = baseChain.begin(); iter2 != baseChain.end(); iter2++) {
        uint64_t thisBase = iter2->first;
        outs() << "         " << format_hex(thisBase, 0) << ":";
        std::vector<AssignGadge *> gadgets = iter2->second;
        for (auto iter3 = gadgets.begin(); iter3 != gadgets.end(); iter3++) {
          outs() << " " << format_hex((*iter3)->block_addr, 0);
        }
        outs() << "\n";
      }
    }
    outs() << "\n";
  }
}

void JumpTargetManager::printGadgetChains(
  std::map<uint64_t, ABaseHeap> &allBaseHeaps) {
  /*for (auto iter = allBaseHeaps.begin(); iter != allBaseHeaps.end(); iter++)
  {
    uint64_t primeBase = iter->first;
    ABaseHeap thisBaseHeap = iter->second;
    outs() <<
  "==========================================================================\n";
    outs() << "primeBase: " << format_hex(primeBase, 0) << "\n";

    std::set<uint64_t> relatedUnexploredBases =
  thisBaseHeap.relatedUnexploredBases; outs() << "     relatedBases:"; for (auto
  iter1 = relatedUnexploredBases.begin(); iter1 != relatedUnexploredBases.end();
  iter1++)
    {
      outs() << " " << format_hex(*iter1, 0) ;
    }
    outs() << "\n";

    std::vector<std::vector<AssignGadge *>> allGadgetChains =
  thisBaseHeap.gadgetChains; int i = 0; for (auto iter1 =
  allGadgetChains.begin(); iter1 != allGadgetChains.end(); iter1++)
    {
      i++;
      outs() << "     gadgetChain" <<  i << ":";
      std::vector<AssignGadge *> gadgets = *iter1;
      for (auto iter3 = gadgets.begin(); iter3 != gadgets.end(); iter3++)
      {
        outs() << " " << format_hex((*iter3)->block_addr, 0);
      }
      outs() << "\n";
    }
    outs() << "\n";
  }*/
}

void JumpTargetManager::generateCFG() {
  if (!CFG)
    return;
  /********************
   * 1.全部cfg:allcfg
   * 2.链的结尾块地址、存entry的寄存器、entry
   * 3.包含间接指令的块地址：
   *
   * ******************/

  // AllSrcToDests

  //<SrcAddr, AddrOfReg, reg, entry>
  // auto InfoPath = outputpath + ".EntryInfo.csv";
  // std::ofstream Info;

  // < pc, 1 >
  // IndirectJmpBlocks
  // IndirectCallBlocks
}
