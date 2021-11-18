#ifndef JUMPTARGETMANAGER_H
#define JUMPTARGETMANAGER_H

//
// This file is distributed under the MIT License. See LICENSE.md for details.
//

// Standard includes
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

// Boost includes
#include <boost/icl/interval_map.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/type_traits/is_same.hpp>

// LLVM includes
#include "llvm/ADT/Optional.h"
#include "llvm/IR/Instructions.h"

// Local libraries includes
#include "grin/Support/IRHelpers.h"
#include "grin/Support/grin.h"

// Local includes
#include "BinaryFile.h"
#include "NoReturnAnalysis.h"

#include "PTCInterface.h"

// Forward declarations
namespace llvm {
class BasicBlock;
class Function;
class Instruction;
class LLVMContext;
class Module;
class SwitchInst;
class StoreInst;
class Value;
} // namespace llvm

class JumpTargetManager;

template<typename Map>
typename Map::const_iterator
containing(Map const &m, typename Map::key_type const &k) {
  typename Map::const_iterator it = m.upper_bound(k);
  if (it != m.begin()) {
    return --it;
  }
  return m.end();
}

template<typename Map>
typename Map::iterator containing(Map &m, typename Map::key_type const &k) {
  typename Map::iterator it = m.upper_bound(k);
  if (it != m.begin()) {
    return --it;
  }
  return m.end();
}

/// \brief Transform constant writes to the PC in jumps
///
/// This pass looks for all the calls to the `ExitTB` function calls, looks for
/// the last write to the PC before them, checks if the written value is
/// statically known, and, if so, replaces it with a jump to the corresponding
/// translated code. If the write to the PC is not constant, no action is
/// performed, and the call to `ExitTB` remains there for later handling.
class TranslateDirectBranchesPass : public llvm::ModulePass {
public:
  static char ID;

  TranslateDirectBranchesPass() : llvm::ModulePass(ID), JTM(nullptr) {}

  TranslateDirectBranchesPass(JumpTargetManager *JTM) :
    ModulePass(ID),
    JTM(JTM) {}

  void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

  bool runOnModule(llvm::Module &M) override;

  /// \brief Remove all the constant writes to the PC
  bool pinConstantStore(llvm::Function &F);

  /// \brief Remove all the PC-writes for which a set of (approximate) targets
  ///        is known
  bool pinJTs(llvm::Function &F);

  /// Introduces a fallthrough branch if there's no store to PC before the last
  /// call to an helper
  ///
  /// \return true if the \p Call has been handled (i.e. a fallthrough jump has
  ///         been inserted.
  bool forceFallthroughAfterHelper(llvm::CallInst *Call);

private:
  /// Obtains the absolute address of the PC corresponding to the original
  /// assembly instruction coming after the specified LLVM instruction
  uint64_t getNextPC(llvm::Instruction *TheInstruction);

private:
  JumpTargetManager *JTM;
};

namespace CFGForm {

/// \brief Possible forms the CFG we're building can assume.
///
/// Generally the CFG should stay in the SemanticPreservingCFG state, but it
/// can be temporarily changed to make certain analysis (e.g., computation of
/// the dominator tree) more effective for certain purposes.
enum Values {
  /// The CFG is an unknown state
  UnknownFormCFG,
  /// The dispatcher jumps to all the jump targets, and all the indirect jumps
  /// go to the dispatcher
  SemanticPreservingCFG,
  /// The dispatcher only jumps to jump targets without other predecessors and
  /// indirect jumps do not go to the dispatcher, but to an unreachable
  /// instruction
  RecoveredOnlyCFG,
  /// Similar to RecoveredOnlyCFG, but all jumps forming a function call are
  /// converted to jumps to the return address
  NoFunctionCallsCFG
};

inline const char *getName(Values V) {
  switch (V) {
  case UnknownFormCFG:
    return "UnknownFormCFG";
  case SemanticPreservingCFG:
    return "SemanticPreservingCFG";
  case RecoveredOnlyCFG:
    return "RecoveredOnlyCFG";
  case NoFunctionCallsCFG:
    return "NoFunctionCallsCFG";
  }

  grin_abort();
}

} // namespace CFGForm

class legalValue {
public:
  legalValue(std::vector<llvm::Value *> v,
             std::vector<llvm::Instruction *> inst) :
    value(v),
    I(inst) {}

  legalValue(std::vector<llvm::Instruction *> inst) : I(inst) {}

  // Value stack and Instruction stack
  std::vector<llvm::Value *> value;
  std::vector<llvm::Instruction *> I;
};

class JumpTargetManager {
private:
  using interval_set = boost::icl::interval_set<uint64_t>;
  using interval = boost::icl::interval<uint64_t>;

public:
  /* Determine whether to repeat to TB.*/
  unsigned int haveBB;
  uint64_t textStartAddr;
  uint64_t textEndAddr;
  llvm::GlobalVariable *elf_name;
  std::string outputpath;

  void harvestbranchBasicBlock(
    uint64_t nextAddr,
    uint64_t thisAddr,
    llvm::BasicBlock *thisBlock,
    uint32_t size,
    std::map<std::string, llvm::BasicBlock *> &branchlabeledBasicBlock);
  int64_t getDestBRPCWrite(llvm::BasicBlock *block);
  bool haveTranslatedPC(uint64_t pc, uint64_t next);

  // destAddr, srcBB, srcAddr.
  std::vector<std::tuple<uint64_t, llvm::BasicBlock *, uint64_t>> BranchTargets;

  void clearRegs();
  void harvestCallBasicBlock(llvm::BasicBlock *thisBlock, uint64_t thisAddr);
  void recordFunArgs(uint64_t entry, llvm::BasicBlock *thisBlock);
  bool haveFuncPointer(uint64_t fp, llvm::BasicBlock *thisBlock);

  std::map<uint64_t, std::vector<uint64_t>> FuncArgs;
  void recoverArgs(uint64_t entry);
  void getArgsEnv(uint64_t entry);
  std::map<uint64_t, uint64_t> RecoverArgs;
  std::map<uint64_t, std::pair<uint64_t, std::vector<uint64_t>>> RecoverEnv;

  void harvestBTBasicBlock(llvm::BasicBlock *thisBlock,
                           uint64_t thisAddr,
                           uint64_t destAddr);

  enum LastAssignmentResult {
    CurrentBlockValueDef, /* Case 1: Return value def instruction
                           * Case 2: Current BasicBlock have many use of
                           *   value but no assign operating, return def
                           * instruction */
    NextBlockOperating, /* Case 1: Explort next BasicBlock of operating this
                         * value Case 2: Current BasicBlock have many use of
                         *   value but no assign operating, explorting next
                         *   BasicBlock of operating this value */
    CurrentBlockLastAssign, // Return last assignment of current of BasicBlock

    ConstantValueAssign,
    UnknowResult
  };

  enum TrackbackMode {
    FullMode, /* Stopping trackbacking analysis until encountering 'rsp' */
    CrashMode,

    JumpTableMode, /* Stopping trackbacking analysis until encountering
                    * 'rax rbx rcx rdx rsi rdi' */
    InterprocessMode, /* Stopping trackbacking analysis until encountering
                       * 'rsp' N times*/
    RangeMode, /* As long as encountering assignment of register and constant,
                * stop backtracking*/
    TestMode
  };

  using IndirectBlocksMap = std::map<uint64_t, bool>;
  IndirectBlocksMap IndirectCallBlocks;
  IndirectBlocksMap CallTable;
  IndirectBlocksMap IndirectJmpBlocks;
  IndirectBlocksMap DirectJmpBlocks;
  IndirectBlocksMap JmpTable;
  IndirectBlocksMap RetBlocks;
  std::map<uint64_t, uint64_t> CallBranches;
  std::map<uint64_t, std::set<uint64_t>> CondBranches;
  void harvestNextAddrofBr();
  void StatisticsLog(std::string OutputPath);
  void InitialOutput(std::string OutputPath);

  std::set<uint64_t> BranchAddrs;

  llvm::BasicBlock *obtainJTBB(uint64_t PC, JTReason::Values Reason);
  llvm::BasicBlock *obtainJTBB(uint64_t PC);

  using SrcToDestsMap = std::map<uint64_t, std::set<uint64_t>>;
  SrcToDestsMap SrcToDests;
  SrcToDestsMap AllSrcToDests;
  void
  generatePartCFG(uint64_t src, uint64_t dest, llvm::BasicBlock *thisBlock);
  SrcToDestsMap SrcToDestsWithNext;
  void generatePartCFGWithNext(uint64_t src,
                               uint64_t dest,
                               llvm::BasicBlock *thisBlock);

  SrcToDestsMap allcfg;
  void generateCFG();

  using StaticAddrsMap = std::map<uint64_t, uint32_t>;
  StaticAddrsMap StaticAddrs;
  StaticAddrsMap UnexploreStaticAddr;
  void harvestStaticAddr(llvm::BasicBlock *thisBlock);
  void harvestJumpTableAddr(llvm::BasicBlock *thisBlock, uint64_t thisAddr);
  void harvestVirtualTableAddr(llvm::BasicBlock *thisBlock, uint64_t base);
  int64_t GetConst(llvm::Instruction *I, llvm::Value *v);
  void registerJumpTable(llvm::BasicBlock *thisBlock,
                         llvm::Instruction *shl,
                         llvm::Instruction *add,
                         uint64_t thisAddr,
                         int64_t base,
                         int64_t offset);
  bool handleStaticAddr(void);
  void harvestBlockPCs(std::vector<uint64_t> &BlockPCs);
  void StaticToUnexplore(void);
  void CallNextToStaticAddr(uint32_t PC);
  StaticAddrsMap JumpTableBase;

  void purgeIllegalTranslation(llvm::BasicBlock *thisBlock);

  std::vector<uint64_t> IllegalStaticAddrs;
  bool isIllegalStaticAddr(uint64_t pc);

  void handleInvalidAddr(uint64_t &DynamicVirtualAddress);
  void handleLibCalling(uint64_t &DynamicVirtualAddress);

  void handleIndirectCall(llvm::BasicBlock *thisBlock,
                          uint64_t thisAddr,
                          bool StaticFlag);
  uint64_t handleIllegalMemoryAccess(llvm::BasicBlock *thisBlock,
                                     uint64_t thisAddr,
                                     size_t ConsumedSize);
  llvm::BasicBlock *getSplitedBlock(llvm::BranchInst *branch);
  uint32_t REGLABLE(uint32_t RegOP);
  void handleIllegalJumpAddress(llvm::BasicBlock *thisBlock, uint64_t thisAddr);
  void handleIndirectJmp(llvm::BasicBlock *thisBlock,
                         uint64_t thisAddr,
                         bool StaticFlag);
  void getIllegalValueDFG(llvm::Value *v,
                          llvm::Instruction *I,
                          llvm::BasicBlock *thisBlock,
                          std::vector<llvm::Instruction *> &DataFlow,
                          TrackbackMode TackType,
                          uint32_t &userCodeFlag);
  uint32_t getLegalValueRange(llvm::BasicBlock *thisBlock);
  void analysisLegalValue(std::vector<llvm::Instruction *> &DataFlow,
                          std::vector<legalValue> &legalSet);
  uint32_t range;

  using LastAssignmentResultWithInst = std::pair<enum LastAssignmentResult,
                                                 llvm::Instruction *>;
  LastAssignmentResultWithInst getLastAssignment(llvm::Value *v,
                                                 llvm::User *userInst,
                                                 llvm::BasicBlock *currentBB,
                                                 TrackbackMode TrackType,
                                                 uint32_t &NUMOFCONST);
  bool isAccessMemInst(llvm::Instruction *I);
  uint64_t getInstructionPC(llvm::Instruction *I);
  size_t getPosition(llvm::Instruction *I);
  std::pair<bool, uint32_t> islegalAddr(llvm::Value *v);
  bool isDataSegmAddr(uint64_t PC);
  bool isELFDataSegmAddr(uint64_t PC);
  uint32_t StrToInt(const char *str);

  std::vector<uint64_t> TempCPURegister;
  void storeCPURegister();
  void cleanCPURegister();
  void recoverCPURegister();
  bool isCase1(llvm::Instruction *I, uint64_t global);
  bool isCase2(llvm::Instruction *I);
  void getGloFromTempReg(llvm::Instruction *I,
                         std::map<uint32_t, uint64_t> &GloData);
  uint32_t getOP(llvm::Value *v);
  bool getStaticAddrfromDestRegs1(llvm::Instruction *I, uint64_t global);
  uint64_t getStaticAddrfromDestRegs(llvm::Instruction *I,
                                     uint64_t bound,
                                     std::pair<uint64_t, uint32_t> &entryinfo);
  uint64_t getStaticAddrfromDestRegs(llvm::Instruction *I, uint64_t bound);
  bool getGlobalDatafromRegs(llvm::Instruction *I, int64_t pre);
  uint64_t getGlobalDatafromDestRegs(llvm::Instruction *I);
  std::pair<uint32_t, uint64_t>
  getLastOperandandNextPC(llvm::Instruction *I, llvm::Instruction *current);
  bool isReachtoCurrent(llvm::StoreInst *store, llvm::Instruction *cur);
  std::vector<uint32_t> getIndexReg(llvm::Instruction *I);
  uint32_t getOffsetReg(llvm::Instruction *I);
  void harvestCodePointerInDataSegment(int64_t pos);
  void DirectCodePointerHarvest(int64_t pos);
  void scanMemoryBlock(uint64_t start,
                       uint64_t end,
                       llvm::BasicBlock *thisBlock,
                       uint64_t thisAddr);
  void scanAllUnexplore();

  uint64_t BlockBound;
  void runGlobalGadget(llvm::BasicBlock *gadget,
                       bool oper,
                       llvm::Instruction *global_I,
                       uint32_t op,
                       bool indirect,
                       uint32_t isloop,
                       std::set<uint64_t> &tmpGlobal);
  void ConstOffsetExec(llvm::BasicBlock *gadget,
                       uint64_t thisAddr,
                       uint64_t current_pc,
                       bool oper,
                       llvm::Instruction *global_I,
                       uint32_t op,
                       bool indirect,
                       uint32_t isloop,
                       std::set<uint64_t> &tempVec,
                       std::set<uint64_t> &JTtargets);
  void VarOffsetExec(llvm::BasicBlock *gadget,
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
                     std::set<uint64_t> &JTtargets);
  bool isGOT(uint64_t pc);
  bool isROData(uint64_t pc);
  bool isGlobalData(uint64_t pc);
  bool isGlobalDataNoRO(uint64_t pc);
  bool isJumpTabType(llvm::Instruction *I);
  bool isRecordGlobalBase(uint64_t base);
  int64_t isRecordGadgetBlock(uint64_t base);
  bool isMemoryBlockBase(llvm::Instruction *I);
  bool ishelperPC(llvm::Instruction *I);
  std::pair<uint32_t, bool> haveBinaryOperation(llvm::Instruction *I);
  bool haveDefOperation(llvm::Instruction *I, llvm::Value *v);
  bool haveDef2OP(llvm::Instruction *I, uint32_t op);
  void haveGlobalDatainRegs(std::map<uint32_t, uint64_t> &GloData);
  void handleGlobalDataGadget(llvm::BasicBlock *thisBlock,
                              std::map<uint32_t, uint64_t> &GloData);
  void handleGlobalStaticAddr(void);
  void loadMultProcessSAs(void);
  // std::vector<uint64_t, AssignGadge> assign_gadge;
  std::map<uint64_t, uint32_t> AllGlobalAddr;
  std::map<uint64_t, uint64_t> AllUnexploreGlobalAddr;
  std::map<uint64_t, uint64_t> primeBases;
  bool isRecordCandidataAddr;
  std::map<uint64_t, uint32_t> AllGloCandidataAddr;
  std::map<llvm::BasicBlock *, uint32_t> AllGadget;
  std::map<llvm::BasicBlock *, uint32_t> AllStaticGadget;

  class AssignGadge {
  public:
    AssignGadge() :
      global_addr(0),
      pre(-1),
      global_I(nullptr),
      op(UndefineOP),
      block_addr(0),
      operation_block(nullptr),
      static_addr_block(nullptr),
      static_global_I(nullptr),
      static_op(UndefineOP),
      indirect(false),
      isloop(0),
      end(true) {}
    AssignGadge(uint64_t addr) :
      global_addr(addr),
      pre(-1),
      global_I(nullptr),
      op(UndefineOP),
      block_addr(0),
      operation_block(nullptr),
      static_addr_block(nullptr),
      static_global_I(nullptr),
      static_op(UndefineOP),
      indirect(false),
      isloop(0),
      end(true) {}

    uint64_t global_addr;
    int64_t pre;
    llvm::Instruction *global_I;
    uint32_t op;
    uint64_t block_addr;
    llvm::BasicBlock *operation_block;

    llvm::BasicBlock *static_addr_block;
    llvm::Instruction *static_global_I;
    uint32_t static_op;
    bool indirect;
    uint32_t isloop;
    bool end;
  };

  struct ABaseHeap {
    std::set<uint64_t> relatedUnexploredBases;
    std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
      allGadgets;
    std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
      gadgetChains;
  };
  void testFunction();
  void testDebugFunction();
  void printAllGadgets(std::vector<ABaseHeap> &allBaseHeaps);
  void printGadgetChains(std::map<uint64_t, ABaseHeap> &allBaseHeaps);
  void readDebugInfo(std::string OutputPath);
  using GROUP = std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>;
  using GADGETCHAINS = std::vector<
    std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>;

  void CodePointerharvestInOptmChains(uint64_t reserve, GROUP group);
  void CodePointerharvestInOptmChains(uint64_t reserve,
                                      std::vector<AssignGadge *> chain);
  void MultiProcessCodePointerharvest(ABaseHeap &abheap);
  void runChain(uint64_t reserve, std::vector<AssignGadge *> chain);
  void runChain(uint64_t reserve, GROUP group);
  static int ChainsProcess(void *Buf);
  void MultiProcessGroupChains(uint64_t base, GADGETCHAINS &gadgetChains);
  static int GadgetChainsProcess(void *Buf);

  uint64_t DataSegmStartAddr;
  uint64_t DataSegmEndAddr;
  uint64_t ro_StartAddr;
  uint64_t ro_EndAddr;
  uint64_t text_StartAddr;
  uint64_t codeSeg_StartAddr;

  /* Judging whether the Block is User define Block area*/
  uint32_t belongToUBlock(llvm::BasicBlock *block);

  /* Have explored branches of CFG
   * <dest BB, dest Addr, source BB, source Addr> */
  std::vector<
    std::tuple<llvm::BasicBlock *, uint64_t, llvm::BasicBlock *, uint64_t>>
    partCFG;
  // <dest BB,source BB>
  using NODETYPE = std::pair<llvm::BasicBlock *, llvm::BasicBlock *>;
  NODETYPE nodepCFG;
  void pushpartCFGStack(llvm::BasicBlock *dest,
                        uint64_t DAddr,
                        llvm::BasicBlock *src,
                        uint64_t SAddr);
  void searchpartCFG(std::map<llvm::BasicBlock *, llvm::BasicBlock *> &DONE);

private:
  void foldStack(legalValue *&relatedInstPtr);

  llvm::Constant *foldSet(std::vector<legalValue> &legalSet, uint64_t n);

  void handleMemoryAccess(llvm::Instruction *current,
                          llvm::Instruction *next,
                          std::vector<legalValue> &legalSet,
                          legalValue *&relatedInstPtr);
  void handleSelectOperation(llvm::Instruction *current,
                             llvm::Instruction *next,
                             std::vector<legalValue> &legalSet,
                             legalValue *&relatedInstPtr);
  void handleBinaryOperation(llvm::Instruction *current,
                             llvm::Instruction *next,
                             std::vector<legalValue> &legalSet,
                             legalValue *&relatedInstPtr);
  void handleConversionOperations(llvm::Instruction *current,
                                  std::vector<legalValue> &legalSet,
                                  legalValue *&relatedInstPtr);

  llvm::Value *payBinaryValue(llvm::Value *v);
  bool isCorrelationWithNext(llvm::Value *preValue, llvm::Instruction *Inst);
  void set2ptr(llvm::Instruction *next,
               std::vector<legalValue> &legalSet,
               legalValue *&relatedInstPtr);
  std::vector<llvm::Value *> PushTemple(llvm::Value *v) {
    std::vector<llvm::Value *> temp;
    temp.push_back(v);
    return temp;
  }
  std::vector<llvm::Instruction *> PushTemple(llvm::Instruction *I) {
    std::vector<llvm::Instruction *> temp;
    temp.push_back(I);
    return temp;
  }

public:
  using BlockWithAddress = std::pair<uint64_t, llvm::BasicBlock *>;
  static const BlockWithAddress NoMoreTargets;

  class JumpTarget {
  public:
    JumpTarget() : BB(nullptr), Reasons(0) {}
    JumpTarget(llvm::BasicBlock *BB) : BB(BB), Reasons(0) {}
    JumpTarget(llvm::BasicBlock *BB, JTReason::Values Reason) :
      BB(BB),
      Reasons(static_cast<uint32_t>(Reason)) {}

    llvm::BasicBlock *head() const { return BB; }
    bool hasReason(JTReason::Values Reason) const {
      return (Reasons & static_cast<uint32_t>(Reason)) != 0;
    }
    void setReason(JTReason::Values Reason) {
      Reasons |= static_cast<uint32_t>(Reason);
    }
    uint32_t getReasons() const { return Reasons; }

    bool isOnlyReason(JTReason::Values Reason) const {
      return (hasReason(Reason)
              and (Reasons & ~static_cast<uint32_t>(Reason)) == 0);
    }

    std::vector<const char *> getReasonNames() const {
      std::vector<const char *> Result;

      uint32_t LastReason = static_cast<uint32_t>(JTReason::LastReason);
      for (unsigned Reason = 1; Reason <= LastReason; Reason <<= 1) {
        JTReason::Values R = static_cast<JTReason::Values>(Reason);
        if (hasReason(R))
          Result.push_back(JTReason::getName(R));
      }

      return Result;
    }

    std::string describe() const {
      std::stringstream SS;
      SS << getName(BB) << ":";

      for (const char *ReasonName : getReasonNames())
        SS << " " << ReasonName;

      return SS.str();
    }

  private:
    llvm::BasicBlock *BB;
    uint32_t Reasons;
  };

public:
  using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

  /// \param TheFunction the translated function.
  /// \param PCReg the global variable representing the program counter.
  /// \param Binary reference to the information about a given binary, such as
  ///        segments and symbols.
  JumpTargetManager(llvm::Function *TheFunction,
                    llvm::Value *PCReg,
                    const BinaryFile &Binary);

  JumpTargetManager(llvm::Function *TheFunction,
                    llvm::Value *PCReg,
                    const BinaryFile &Binary,
                    llvm::GlobalVariable *ELFName);

  /// \brief Transform the IR to represent the request form of CFG
  void setCFGForm(CFGForm::Values NewForm);

  CFGForm::Values cfgForm() const { return CurrentCFGForm; }

  /// \brief Collect jump targets from the program's segments
  void harvestGlobalData();

  /// Handle a new program counter. We might already have a basic block for that
  /// program counter, or we could even have a translation for it. Return one
  /// of these, if appropriate.
  ///
  /// \param PC the new program counter.
  /// \param ShouldContinue an out parameter indicating whether the returned
  ///        basic block was just a placeholder or actually contains a
  ///        translation.
  ///
  /// \return the basic block to use from now on, or `nullptr` if the program
  ///         counter is not associated to a basic block.
  // TODO: return pair
  llvm::BasicBlock *newPC(uint64_t PC, bool &ShouldContinue);

  /// \brief Save the PC-Instruction association for future use
  void registerInstruction(uint64_t PC, llvm::Instruction *Instruction);

  /// \brief Return the most recent instruction writing the program counter
  ///
  /// Note that the search is performed only in the current basic block.  The
  /// function will assert if the write instruction is not found.
  ///
  /// \param TheInstruction instruction from which start the search.
  ///
  /// \return a pointer to the last `StoreInst` writing the program counter, or
  ///         `nullptr` if a call to an helper has been found before the write
  ///         to the PC.
  llvm::StoreInst *getPrevPCWrite(llvm::Instruction *TheInstruction);

  /// \brief Return a pointer to the `exitTB` function
  ///
  /// `exitTB` is called when jump to the current value of the PC must be
  /// performed.
  llvm::Function *exitTB() { return ExitTB; }

  /// \brief Pop from the list of program counters to explore
  ///
  /// \return a pair containing the PC and the initial block to use, or
  ///         JumpTarget::NoMoreTargets if we're done.
  BlockWithAddress peek();

  /// \brief Return true if no unexplored jump targets are available
  bool empty() { return Unexplored.empty(); }

  /// \brief Return true if the whole [\p Start,\p End) range is in an
  ///        executable segment
  bool isExecutableRange(uint64_t Start, uint64_t End) const {
    for (std::pair<uint64_t, uint64_t> Range : ExecutableRanges)
      if (Range.first <= Start && Start < Range.second && Range.first <= End
          && End < Range.second)
        return true;
    return false;
  }

  /// \brief Return true if the given PC respects the input architecture's
  ///        instruction alignment constraints
  bool isInstructionAligned(uint64_t PC) const {
    return PC % Binary.architecture().instructionAlignment() == 0;
  }

  /// \brief Return true if the given PC can be executed by the current
  ///        architecture
  bool isPC(uint64_t PC) const {
    return isExecutableAddress(PC) && isInstructionAligned(PC);
  }

  /// \brief Return true if the given PC is a jump target
  bool isJumpTarget(uint64_t PC) const { return JumpTargets.count(PC); }

  /// \brief Return true if the given basic block corresponds to a jump target
  bool isJumpTarget(llvm::BasicBlock *BB) {
    if (BB->empty())
      return false;

    uint64_t PC = getPCFromNewPCCall(&*BB->begin());
    if (PC != 0)
      return isJumpTarget(PC);

    return false;
  }

  /// \brief Return true if \p PC is in an executable segment
  bool isExecutableAddress(uint64_t PC) const {
    // for (std::pair<uint64_t, uint64_t> Range : ExecutableRanges)
    if (text_StartAddr <= PC && PC < ro_StartAddr)
      return true;
    return false;
  }

  /// \brief Get the basic block associated to the original address \p PC
  ///
  /// If the given address has never been met, assert.
  ///
  /// \param PC the PC for which a `BasicBlock` is requested.
  llvm::BasicBlock *getBlockAt(uint64_t PC);

  /// \brief Return, and, if necessary, register the basic block associated to
  ///        \p PC
  ///
  /// This function can return `nullptr`.
  ///
  /// \param PC the PC for which a `BasicBlock` is requested.
  ///
  /// \return a `BasicBlock`, it might be newly created and empty, empty and
  ///         created in the past or even a `BasicBlock` already containing the
  ///         translated code.  It might also return `nullptr` if the PC is not
  ///         valid or another error occurred.
  llvm::BasicBlock *registerJT(uint64_t PC, JTReason::Values Reason);
  bool hasJT(uint64_t PC) { return JumpTargets.count(PC) != 0; }

  std::map<uint64_t, JumpTarget>::const_iterator begin() const {
    return JumpTargets.begin();
  }

  std::map<uint64_t, JumpTarget>::const_iterator end() const {
    return JumpTargets.end();
  }

  void registerJT(llvm::BasicBlock *BB, JTReason::Values Reason) {
    grin_assert(!BB->empty());
    auto *CallNewPC = llvm::dyn_cast<llvm::CallInst>(&*BB->begin());
    grin_assert(CallNewPC != nullptr);
    llvm::Function *Callee = CallNewPC->getCalledFunction();
    grin_assert(Callee != nullptr && Callee->getName() == "newpc");
    registerJT(getLimitedValue(CallNewPC->getArgOperand(0)), Reason);
  }

  /// \brief As registerJT, but only if the JT has already been registered
  void markJT(uint64_t PC, JTReason::Values Reason) {
    if (isJumpTarget(PC))
      registerJT(PC, Reason);
  }

  /// \brief Removes a `BasicBlock` from the SET's visited list
  void unvisit(llvm::BasicBlock *BB);

  /// \brief Checks if \p BB is a basic block generated during translation
  bool isTranslatedBB(llvm::BasicBlock *BB) const {
    return BB != anyPC() && BB != unexpectedPC() && BB != dispatcher()
           && BB != dispatcherFail();
  }

  /// \brief Return the dispatcher basic block.
  ///
  /// \note Do not use this for comparison with successors of translated code,
  ///       use isTranslatedBB instead.
  llvm::BasicBlock *dispatcher() const { return Dispatcher; }

  /// \brief Return the basic block handling an unknown PC in the dispatcher
  llvm::BasicBlock *dispatcherFail() const { return DispatcherFail; }

  /// \brief Return the basic block handling a jump to any PC
  llvm::BasicBlock *anyPC() const { return AnyPC; }

  /// \brief Return the basic block handling a jump to an unexpected PC
  llvm::BasicBlock *unexpectedPC() const { return UnexpectedPC; }

  bool isPCReg(llvm::Value *TheValue) const { return TheValue == PCReg; }

  llvm::Value *pcReg() const { return PCReg; }

  // TODO: can this be replaced by the corresponding method in
  // GeneratedCodeBasicInfo?
  /// \brief Get the PC associated to \p TheInstruction and the next one
  ///
  /// \return a pair containing the PC associated to \p TheInstruction and the
  ///         next one.
  std::pair<uint64_t, uint64_t> getPC(llvm::Instruction *TheInstruction) const;

  // TODO: can this be replaced by the corresponding method in
  // GeneratedCodeBasicInfo?
  uint64_t getNextPC(llvm::Instruction *TheInstruction) const {
    auto Pair = getPC(TheInstruction);
    return Pair.first + Pair.second;
  }

  /// \brief Read an integer number from a segment
  ///
  /// \param Address the address from which to read.
  /// \param Size the size of the read in bytes.
  ///
  /// \return a `ConstantInt` with the read value or `nullptr` in case it wasn't
  ///         possible to read the value (e.g., \p Address is not inside any of
  ///         the segments).
  llvm::ConstantInt *
  readConstantInt(llvm::Constant *Address,
                  unsigned Size,
                  BinaryFile::Endianess E = BinaryFile::OriginalEndianess);

  /// \brief Reads a pointer-sized value from a segment
  /// \see readConstantInt
  llvm::Constant *
  readConstantPointer(llvm::Constant *Address,
                      llvm::Type *PointerTy,
                      BinaryFile::Endianess E = BinaryFile::OriginalEndianess);

  /// \brief Increment the counter of emitted branches since the last reset
  void newBranch() { NewBranches++; }

  /// \brief Finalizes information about the jump targets
  ///
  /// Call this function once no more jump targets can be discovered.  It will
  /// fix all the pending information. In particular, those pointers to code
  /// that have never been touched by SET will be considered and their pointee
  /// will be marked with UnusedGlobalData.
  ///
  /// This function also fixes the "anypc" and "unexpectedpc" basic blocks to
  /// their proper behavior.
  void finalizeJumpTargets() {
    translateIndirectJumps();

    unsigned ReadSize = Binary.architecture().pointerSize() / 8;
    for (uint64_t MemoryAddress : UnusedCodePointers) {
      // Read using the original endianess, we want the correct address
      uint64_t PC = *Binary.readRawValue(MemoryAddress, ReadSize);

      // Set as reason UnusedGlobalData and ensure it's not empty
      llvm::BasicBlock *BB = registerJT(PC, JTReason::UnusedGlobalData);
      grin_assert(!BB->empty());
    }

    // We no longer need this information
    freeContainer(UnusedCodePointers);
  }

  void createJTReasonMD() {
    using namespace llvm;

    Function *CallMarker = TheModule.getFunction("function_call");
    if (CallMarker != nullptr) {
      auto unwrapBA = [](Value *V) {
        return cast<BlockAddress>(V)->getBasicBlock();
      };
      for (User *U : CallMarker->users()) {
        if (CallInst *Call = dyn_cast<CallInst>(U)) {
          if (isa<BlockAddress>(Call->getOperand(0)))
            registerJT(unwrapBA(Call->getOperand(0)), JTReason::Callee);
          registerJT(unwrapBA(Call->getOperand(1)), JTReason::ReturnAddress);
        }
      }
    }

    // Tag each jump target with its reasons
    for (auto &P : JumpTargets) {
      JumpTarget &JT = P.second;
      TerminatorInst *T = JT.head()->getTerminator();
      // errs()<<(JT.head()->getName())<<"\n";
      // errs()<<JT.head()->empty()<<"      terminator\n";
      grin_assert(T != nullptr);

      std::vector<Metadata *> Reasons;
      for (const char *ReasonName : JT.getReasonNames())
        Reasons.push_back(MDString::get(Context, ReasonName));

      T->setMetadata("grin.jt.reasons", MDTuple::get(Context, Reasons));
    }
  }

  unsigned delaySlotSize() const {
    return Binary.architecture().delaySlotSize();
  }

  const BinaryFile &binary() const { return Binary; }

  /// \brief Return the next call to exitTB after I, or nullptr if it can't find
  ///        one
  llvm::CallInst *findNextExitTB(llvm::Instruction *I);

  // TODO: can we drop this in favor of GeneratedCodeBasicInfo::isJump?
  bool isJump(llvm::TerminatorInst *T) const {
    for (llvm::BasicBlock *Successor : T->successors()) {
      if (!(Successor == Dispatcher || Successor == DispatcherFail
            || isJumpTarget(getBasicBlockPC(Successor))))
        return false;
    }

    return true;
  }

  void registerReadRange(uint64_t Address, uint64_t Size);

  const interval_set &readRange() const { return ReadIntervalSet; }

  NoReturnAnalysis &noReturn() { return NoReturn; }

  /// \brief Return a proper name for the given address, possibly using symbols
  ///
  /// \param Address the address for which a name should be produced.
  ///
  /// \return a string containing the symbol name and, if necessary an offset,
  ///         or if no symbol can be found, just the address.
  std::string nameForAddress(uint64_t Address, uint64_t Size = 1) const;

  /// \brief Register a simple literal collected during translation for
  ///        harvesting
  ///
  /// A simple literal is a literal value found in the input program that is
  /// simple enough not to require SET. The typcal example is the return address
  /// of a function call, that is provided to use by libtinycode in full.
  ///
  /// Simple literals are registered as possible jump targets before attempting
  /// more expensive techniques such as SET.
  void registerSimpleLiteral(uint64_t Address) {
    SimpleLiterals.insert(Address);
  }

private:
  std::set<llvm::BasicBlock *> computeUnreachable();

  /// \brief Translate the non-constant jumps into jumps to the dispatcher
  void translateIndirectJumps();

  /// \brief Helper function to check if an instruction is a call to `newpc`
  ///
  /// \return 0 if \p I is not a call to `newpc`, otherwise the PC address of
  ///         associated to the call to `newpc`
  uint64_t getPCFromNewPCCall(llvm::Instruction *I) {
    if (auto *CallNewPC = llvm::dyn_cast<llvm::CallInst>(I)) {
      if (CallNewPC->getCalledFunction() == nullptr
          || CallNewPC->getCalledFunction()->getName() != "newpc")
        return 0;

      return getLimitedValue(CallNewPC->getArgOperand(0));
    }

    return 0;
  }

  /// \brief Erase \p I, and deregister it in case it's a call to `newpc`
  void eraseInstruction(llvm::Instruction *I) {
    // grin_assert(I->use_empty());

    uint64_t PC = getPCFromNewPCCall(I);
    if (PC != 0)
      OriginalInstructionAddresses.erase(PC);
    I->eraseFromParent();
  }

  /// \brief Drop \p Start and all the descendants, stopping when a JT is met
  void purgeTranslation(llvm::BasicBlock *Start);

  /// \brief Check if \p BB has at least a predecessor, excluding the dispatcher
  bool hasPredecessors(llvm::BasicBlock *BB) const;

  /// \brief Rebuild the dispatcher switch
  ///
  /// Depending on the CFG form we're currently adopting the dispatcher might go
  /// to all the jump targets or only to those who have no other predecessor.
  void rebuildDispatcher();

  // TODO: instead of a gigantic switch case we could map the original memory
  //       area and write the address of the translated basic block at the jump
  //       target
  void
  createDispatcher(llvm::Function *OutputFunction, llvm::Value *SwitchOnPtr);

  template<typename value_type, unsigned endian>
  void findCodePointers(uint64_t StartVirtualAddress,
                        const unsigned char *Start,
                        const unsigned char *End);

  void harvest();

  void handleSumJump(llvm::Instruction *SumJump);

private:
  using BlockMap = std::map<uint64_t, JumpTarget>;
  using InstructionMap = std::map<uint64_t, llvm::Instruction *>;

  llvm::Module &TheModule;
  llvm::LLVMContext &Context;
  llvm::Function *TheFunction;
  /// Holds the association between a PC and the last generated instruction for
  /// the previous instruction.
  InstructionMap OriginalInstructionAddresses;
  /// Holds the association between a PC and a BasicBlock.
  BlockMap JumpTargets;

  std::vector<std::pair<uint64_t, AssignGadge>> assign_gadge;

  /// Queue of program counters we still have to translate.
  std::vector<BlockWithAddress> Unexplored;
  llvm::Value *PCReg;
  llvm::Function *ExitTB;
  RangesVector ExecutableRanges;
  llvm::BasicBlock *Dispatcher;
  llvm::SwitchInst *DispatcherSwitch;
  llvm::BasicBlock *DispatcherFail;
  llvm::BasicBlock *AnyPC;
  llvm::BasicBlock *UnexpectedPC;
  std::set<llvm::BasicBlock *> Visited;

  const BinaryFile &Binary;

  unsigned NewBranches = 0;

  std::set<uint64_t> UnusedCodePointers;
  interval_set ReadIntervalSet;
  NoReturnAnalysis NoReturn;

  CFGForm::Values CurrentCFGForm;
  std::set<llvm::BasicBlock *> ToPurge;
  std::set<uint64_t> SimpleLiterals;
};

template<>
struct BlackListTrait<const JumpTargetManager &, llvm::BasicBlock *>
  : BlackListTraitBase<const JumpTargetManager &> {
  using BlackListTraitBase<const JumpTargetManager &>::BlackListTraitBase;
  bool isBlacklisted(llvm::BasicBlock *Value) {
    return !this->Obj.isTranslatedBB(Value);
  }
};

inline BlackListTrait<const JumpTargetManager &, llvm::BasicBlock *>
make_blacklist(const JumpTargetManager &JTM) {
  return BlackListTrait<const JumpTargetManager &, llvm::BasicBlock *>(JTM);
}

class CFGMap {
public:
  // SrcToDests:generated origin cfg during translation
  // textStartAddr:the Binary's text start address
  // textEndAddr:the Binary's text end address
  CFGMap(std::map<uint64_t, std::set<uint64_t>> &SrcToDests,
         uint64_t textStartAddr,
         uint64_t textEndAddr) {
    startAddr = textStartAddr;
    endAddr = textEndAddr;
    generateCFGMap(SrcToDests);
  }
  ~CFGMap() = default;

private:
  struct CFGNode {
    // the minAddress and maxAddress of the local graph's all nodes down from
    // this node
    uint64_t minAddress;
    uint64_t maxAddress;
    std::set<std::pair<uint64_t const, CFGNode> *> predecessorNodes;
    std::set<std::pair<uint64_t const, CFGNode> *> successorNodes;
    std::set<std::pair<uint64_t const, CFGNode> *> newly_successors;
    // the first branch after this node
    std::pair<uint64_t const, CFGNode> *nextBranch;
  };

  // store every cfg node and relationship
  // key:the node address
  // value:the node's predeccessors and successors
  std::map<uint64_t, CFGNode> cfgMap;

  // textStartAddr:the Binary's text start address
  // textEndAddr:the Binary's text end address
  uint64_t startAddr;
  uint64_t endAddr;

public:
  // print the cfg
  void printCFGMap();

  // insert new cfgnode or edge
  void insertNew(uint64_t sourceAddress, uint64_t successorAddress);

  bool isAddressPrecedent(std::set<uint64_t> nextAddresses, uint64_t addr2);
  bool isNodePrecedent(std::pair<uint64_t const, CFGNode> *node1,
                       std::pair<uint64_t const, CFGNode> *node2);
  bool isBranchPrecedent(std::pair<uint64_t const, CFGNode> *branch1,
                         std::pair<uint64_t const, CFGNode> *branch2,
                         uint64_t minAddress2,
                         uint64_t maxAddress2);

  // find the addr1 and addr2 's connections
  int getAddressOrder(uint64_t addr1, uint64_t addr2);
  // find the addr1 and addr2 's connections
  void getAddressesOrder(uint64_t addr1, std::map<uint64_t, bool> &addr2s);
  // find the relationship between two node in cfg
  int getCfgNodeOrder(std::pair<uint64_t const, CFGNode> *node1,
                      std::pair<uint64_t const, CFGNode> *node2);
  // find the addr1 and addr2 's connections
  void getCfgNodeOrders(
    std::pair<uint64_t const, CFGNode> *node1,
    std::map<std::pair<uint64_t const, CFGNode> *, bool> nodeOrders);
  // if node1 ande node2 are in the same branch
  int getSameBranchNodeOrder(std::pair<uint64_t const, CFGNode> *node1,
                             std::pair<uint64_t const, CFGNode> *node2);
  // get the order of branch1 and branch2
  int getBranchOrder(std::pair<uint64_t const, CFGNode> *branch1,
                     std::pair<uint64_t const, CFGNode> *branch2,
                     uint64_t minAddress1,
                     uint64_t maxAddress1,
                     uint64_t minAddress2,
                     uint64_t maxAddress2);

  // find all next branches of one CFGNode
  std::pair<std::set<std::pair<uint64_t const, CFGMap::CFGNode> *>,
            std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>>
  findNextBranches(std::pair<uint64_t const, CFGNode> *node,
                   uint64_t addr,
                   int numbers);
  void findNextAddresses(uint64_t addr,
                         std::set<uint64_t> &nextAddresses,
                         int numbers);
  void findNextAddressesSequence(uint64_t addr,
                                 std::vector<uint64_t> &nextAddresses,
                                 int numbers);
  std::set<uint64_t> findMergeAddress(uint64_t addr1, uint64_t addr2);

  // get the node
  std::pair<uint64_t const, struct CFGNode> *getNode(uint64_t source_address) {
    std::map<uint64_t const, struct CFGNode>::iterator node;
    node = cfgMap.find(source_address);
    if (node != cfgMap.end())
      return &*node;
    else
      return nullptr;
  }

private:
  // read the origin cfg, store them in the cfgMap
  // SrcToDests: the origin cfg generated during the translation
  void generateCFGMap(std::map<uint64_t, std::set<uint64_t>> &SrcToDests);

  // whether the address is in text section
  bool isTextAddress(uint64_t address);

  // create one node in the cfgMap, and return the node pointer
  std::pair<uint64_t const, CFGNode> *createNode(uint64_t address);

  // insert the edge <source node, successor node>
  void insertEdge(std::pair<uint64_t const, CFGNode> *sourceNode,
                  std::pair<uint64_t const, CFGNode> *successorNode);

  // adjust the node's minAddress and maxAddress
  // adjust the node's nextBranch
  void adjustNode(std::pair<uint64_t const, CFGNode> *node);
  void adjustNodeAddress(std::pair<uint64_t const, CFGNode> *node);
  void adjustNodeNextBranch(std::pair<uint64_t const, CFGNode> *node);
  void adjustNullNextBranch(std::pair<uint64_t const, CFGNode> *node);

  // put iegal successor branch into nextBranches
  void pushIegalSuccessBranches(
    std::queue<std::pair<uint64_t const, CFGNode> *> &nextBranches,
    std::set<std::pair<uint64_t const, CFGNode> *> &allNextBranches,
    std::vector<std::pair<uint64_t const, CFGMap::CFGNode> *>
      &allNextBranchesSequence,
    std::pair<uint64_t const, CFGNode> *branch,
    uint64_t minAddress,
    uint64_t maxAddress);

  // get the minAddress
  uint64_t getMinAddress(std::pair<uint64_t const, struct CFGNode> *node) {
    return (node->second).minAddress;
  }

  // get the maxAddress
  uint64_t getMaxAddress(std::pair<uint64_t const, struct CFGNode> *node) {
    return (node->second).maxAddress;
  }

  // get the successors
  std::set<std::pair<uint64_t const, struct CFGNode> *>
  getSuccessors(std::pair<uint64_t const, struct CFGNode> *node) {
    return (node->second).successorNodes;
  }

  // get the predecessors
  std::set<std::pair<uint64_t const, struct CFGNode> *>
  getPredecessors(std::pair<uint64_t const, struct CFGNode> *node) {
    return (node->second).predecessorNodes;
  }

  // insert one node's one predecessor
  void
  insertPredecessor(std::pair<uint64_t const, struct CFGNode> *node,
                    std::pair<uint64_t const, struct CFGNode> *predecessor) {
    (node->second).predecessorNodes.insert(predecessor);
  }

  // insert one node's one successor
  bool insertSuccessor(std::pair<uint64_t const, struct CFGNode> *node,
                       std::pair<uint64_t const, struct CFGNode> *successor) {
    std::pair<std::set<std::pair<uint64_t const, struct CFGNode> *>::iterator,
              bool>
      ret = (node->second).successorNodes.insert(successor);
    return ret.second;
  }

  // insert one node's one new find successor
  void insertNewlySuccessor(
    std::pair<uint64_t const, struct CFGNode> *node,
    std::pair<uint64_t const, struct CFGNode> *newly_successor) {
    (node->second).newly_successors.insert(newly_successor);
  }

  // set one node's minAddress
  void setMinAddress(std::pair<uint64_t const, struct CFGNode> *node,
                     uint64_t minAddress) {
    (node->second).minAddress = minAddress;
  }

  // set one node's maxAddress
  void setMaxAddress(std::pair<uint64_t const, struct CFGNode> *node,
                     uint64_t maxAddress) {
    (node->second).maxAddress = maxAddress;
  }
};

class BaseHeaps {
  using AssignGadge = JumpTargetManager::AssignGadge;

public:
  //
  BaseHeaps(CFGMap &theCFG,
            CFGMap &theCFGWithNext,
            std::vector<std::pair<uint64_t, AssignGadge>> &assign_gadge,
            std::map<uint64_t, uint64_t> &AllUnexploreGlobalAddr);

  ~BaseHeaps() = default;

private:
  struct GadgetNode {
    std::set<std::pair<AssignGadge *const, GadgetNode> *> nextGadgetNodes;
    std::set<std::pair<AssignGadge *const, GadgetNode> *> preGadgetNodes;
  };
  struct BaseNode {
    bool isDivision = false;
    std::set<std::pair<AssignGadge *const, GadgetNode> *> loopGadgets;
    std::set<std::pair<AssignGadge *const, GadgetNode> *> notLoopGadgets;
    std::map<AssignGadge *, GadgetNode> gadgetsMap;
    // std::set<std::pair<uint64_t const, BaseNode> *> preBaseNodes;
    std::set<std::pair<uint64_t const, BaseNode> *> nextBaseNodes;
  };
  struct BaseHeap {
    std::map<uint64_t, BaseNode> basesInHeap;
    std::pair<uint64_t const, BaseNode> *firstBaseNode;
    std::set<std::pair<AssignGadge *const, GadgetNode> *> allGadgets;
    std::vector<std::vector<uint64_t>> baseChains;
    std::vector<std::vector<AssignGadge *>> gadgetChains;
    // std::map<uint64_t, std::set<uint64_t>> relatedBases;
    std::set<uint64_t> relatedUnexploredBases;
    bool isAlone = false;
  };

  std::map<uint64_t, BaseHeap> AllBaseHeaps;
  CFGMap &theCFG;
  CFGMap &theCFGWithNext;
  std::vector<std::pair<uint64_t, AssignGadge>> &allGadgets;
  std::map<uint64_t, uint64_t> &AllUnexploreGlobalAddr;
  std::vector<std::vector<uint64_t>> baseChains;

  template<class T>
  struct nestedNode {
    std::set<std::pair<T const, nestedNode<T>> *> nextNestedNodes;
    std::set<std::pair<T const, nestedNode<T>> *> preNestedNodes;
  };

private:
  // traverse allGadgets
  void traverseAllGadgets();
  uint64_t traverseBaseChains(
    std::vector<std::vector<uint64_t>> baseChains,
    std::map<uint64_t, std::set<AssignGadge *>> &allBaseGadgets);
  // insert a primeBase into AllBaseHeaps
  std::pair<uint64_t const, BaseHeaps::BaseHeap> *
  insertBaseHeap(uint64_t primeBase);
  // insert a base and gadgets into a baseheap
  std::pair<uint64_t const, BaseHeaps::BaseNode> *insertBaseGadgets(
    std::pair<uint64_t const, BaseHeap> *aBaseHeap,
    std::pair<uint64_t const, std::set<AssignGadge *>> *aBaseGadgets);

  void findUnexploredBases();

  void gadgetClassification(uint64_t base, AssignGadge *theGadget);
  void findRelatedBases(uint64_t thisBase, BaseHeap *thisBaseHeap);
  void generateGadgetsChain(BaseHeap *baseHeap);
  std::pair<uint64_t,
            std::vector<
              std::pair<std::set<std::pair<AssignGadge *const, GadgetNode> *> *,
                        std::pair<AssignGadge *const, GadgetNode> *>>>
  gadgetConnection(
    std::set<std::pair<AssignGadge *const, GadgetNode> *> &thisGadgetMap,
    std::set<std::pair<AssignGadge *const, GadgetNode> *> &gadgetsMap,
    bool isSameBase,
    uint64_t primeBase,
    int number,
    bool preDivision);
  bool loopGadgetsDivision(
    std::map<AssignGadge *, GadgetNode> *gadgetsMap,
    std::set<std::pair<AssignGadge *const, GadgetNode> *> &preAllGadgets,
    std::set<std::pair<AssignGadge *const, GadgetNode> *> &loopGadgets,
    std::set<std::pair<AssignGadge *const, GadgetNode> *> &notLoopGadgets);
  void putGadgets(
    std::set<std::pair<BaseHeaps::AssignGadge *const, BaseHeaps::GadgetNode> *>
      &allGadgets,
    std::vector<AssignGadge *> &finalGadgets);
  void getAllGadgetChains(
    BaseHeap *thisBaseHeap,
    std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
      &gadgetChains);
  void getAllGadgets(
    BaseHeap *thisBaseHeap,
    std::vector<std::vector<std::pair<uint64_t, std::vector<AssignGadge *>>>>
      &gadgetChains);
  void getUsedGadgets(
    std::vector<std::pair<AssignGadge *const, GadgetNode> *> &allGadgets,
    std::vector<AssignGadge *> &usedGadgets);

  // convert graph to chain
  template<class T>
  void graphToChains(std::map<T, nestedNode<T>> &graph,
                     std::set<T> &allPrimes,
                     std::vector<std::vector<T>> &chains);
  template<class T>
  void adjustVisited(std::map<T, nestedNode<T>> &graph,
                     std::vector<T> &visited,
                     std::pair<T const, nestedNode<T>> *thisNode,
                     std::set<std::string> &chainsSet,
                     std::set<T> &allPrimes,
                     T preKey);
  template<class T>
  std::string vectorTostring(std::vector<T> &visited, T notVisited);

  // mutithread
  class ThreadsGuard {
  public:
    ThreadsGuard(std::vector<std::thread> &v) : threads_(v) {}

    ~ThreadsGuard() {
      for (size_t i = 0; i != threads_.size(); ++i) {
        if (threads_[i].joinable()) {
          threads_[i].join();
        }
      }
    }

  private:
    ThreadsGuard(ThreadsGuard &&tg) = delete;
    ThreadsGuard &operator=(ThreadsGuard &&tg) = delete;

    ThreadsGuard(const ThreadsGuard &) = delete;
    ThreadsGuard &operator=(const ThreadsGuard &) = delete;

  private:
    std::vector<std::thread> &threads_;
  };

  class ThreadPool {
  public:
    typedef std::function<void()> task_type;

  public:
    explicit ThreadPool(int n) : stop_(false), tg_(threads_) {
      int nthreads = n;
      if (nthreads <= 0) {
        nthreads = std::thread::hardware_concurrency();
        nthreads = (nthreads == 0 ? 2 : nthreads);
      }

      for (int i = 0; i != nthreads; ++i) {
        threads_.push_back(std::thread([this] {
          while (!stop_.load(std::memory_order_acquire)) {
            task_type task;
            {
              std::unique_lock<std::mutex> ulk(this->mtx_);
              this->cond_.wait(ulk, [this] {
                return stop_.load(std::memory_order_acquire)
                       || !this->tasks_.empty();
              });
              if (stop_.load(std::memory_order_acquire))
                return;
              task = std::move(this->tasks_.front());
              this->tasks_.pop();
            }
            task();
          }
        }));
      }
    }

    ~ThreadPool() {
      stop();
      cond_.notify_all();
    }

    void stop() { stop_.store(true, std::memory_order_release); }

    template<class Function, class... Args>
    std::future<typename std::result_of<Function(Args...)>::type>
    add(Function &&fcn, Args &&... args) {
      typedef typename std::result_of<Function(Args...)>::type return_type;
      typedef std::packaged_task<return_type()> task;

      auto t = std::make_shared<task>(
        std::bind(std::forward<Function>(fcn), std::forward<Args>(args)...));
      auto ret = t->get_future();
      {
        std::lock_guard<std::mutex> lg(mtx_);
        if (stop_.load(std::memory_order_acquire))
          throw std::runtime_error("thread pool has stopped");
        tasks_.emplace([t] { (*t)(); });
      }
      cond_.notify_one();
      return ret;
    }

  private:
    ThreadPool(ThreadPool &&) = delete;
    ThreadPool &operator=(ThreadPool &&) = delete;
    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

  private:
    std::atomic<bool> stop_;
    std::mutex mtx_;
    std::condition_variable cond_;

    std::queue<task_type> tasks_;
    std::vector<std::thread> threads_;
    ThreadsGuard tg_;
  };

public:
  std::vector<JumpTargetManager::ABaseHeap> getBaseHeaps();
};

#endif // JUMPTARGETMANAGER_H
