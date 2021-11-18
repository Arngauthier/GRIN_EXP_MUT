/// \file monotoneframeworkexample.cpp
/// \brief Example of minimal data-flow analysis using the MonotoneFramework
///        class

//
// This file is distributed under the MIT License. See LICENSE.md for details.
//

// Note: this compilation unit should result in no code and no data

namespace llvm {
class Module;
}

// Local libraries includes
#include "grin/Support/MonotoneFramework.h"

namespace ExampleAnalysis {

class Label {};

class LatticeElement {
public:
  static LatticeElement bottom() { return LatticeElement(); }
  LatticeElement copy() { grin_abort(); }
  void combine(const LatticeElement &) { grin_abort(); }
  bool greaterThan(const LatticeElement &) { grin_abort(); }
  void dump() { grin_abort(); }
};

class Interrupt {
public:
  bool requiresInterproceduralHandling() { grin_abort(); }
  LatticeElement &&extractResult() { grin_abort(); }
  bool isReturn() const { grin_abort(); }
};

class Analysis : public MonotoneFramework<Label *,
                                          LatticeElement,
                                          Interrupt,
                                          Analysis,
                                          llvm::iterator_range<Label **>> {
public:
  void assertLowerThanOrEqual(const LatticeElement &A,
                              const LatticeElement &B) const {
    grin_abort();
  }

  Analysis(Label *Entry) : MonotoneFramework(Entry) {}

  void dumpFinalState() const { grin_abort(); }

  llvm::iterator_range<Label **> successors(Label *, Interrupt &) const {
    grin_abort();
  }

  llvm::Optional<LatticeElement> handleEdge(const LatticeElement &Original,
                                            Label *Source,
                                            Label *Destination) const {
    grin_abort();
  }
  size_t successor_size(Label *, Interrupt &) const { grin_abort(); }
  Interrupt createSummaryInterrupt() { grin_abort(); }
  Interrupt createNoReturnInterrupt() const { grin_abort(); }
  LatticeElement extremalValue(Label *) const { grin_abort(); }
  LabelRange extremalLabels() const { grin_abort(); }
  Interrupt transfer(Label *) { grin_abort(); }
};

inline void testFunction() {
  Label Entry;
  Analysis Example(&Entry);
  Example.initialize();
  Example.run();
}

} // namespace ExampleAnalysis
