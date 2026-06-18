#pragma once

#include "scanner.h"

#include <iosfwd>

namespace rop {

void PrintText    (std::ostream& os, const PeImage* img,
                   const std::vector<Gadget>& gadgets, const Options& opt);
void PrintJson    (std::ostream& os, const PeImage* img,
                   const std::vector<Gadget>& gadgets, const Options& opt);
void PrintRopper  (std::ostream& os, const PeImage* img,
                   const std::vector<Gadget>& gadgets, const Options& opt);
void PrintPwntools(std::ostream& os, const PeImage* img,
                   const std::vector<Gadget>& gadgets, const Options& opt);

void PrintBatchText(std::ostream& os, const BatchResult& br, const Options& opt);
void PrintBatchJson(std::ostream& os, const BatchResult& br, const Options& opt);

} // namespace rop
