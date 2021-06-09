#pragma once

#define FLUSH_TLB Sleep(1)

struct pt_entries
{
	std::pair<ppml4e, pml4e>	pml4;
	std::pair<ppdpte, pdpte>	pdpt;
	std::pair<ppde, pde>		pd;
	std::pair<ppte, pte>		pt;
};