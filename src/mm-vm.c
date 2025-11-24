/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

//#ifdef MM_PAGING
/*
 * PAGING based Memory Management
 * Virtual memory module mm/mm-vm.c
 */

#include "string.h"
#include "mm.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#ifdef MM64
#include "mm64.h"
#endif

/*get_vma_by_num - get vm area by numID */
struct vm_area_struct *get_vma_by_num(struct mm_struct *mm, int vmaid)
{
  if (mm == NULL) return NULL;

  struct vm_area_struct *pvma = mm->mmap;

  if (mm->mmap == NULL) return NULL;

  while (pvma != NULL)
  {
    if (pvma->vm_id == vmaid)
      return pvma;
    pvma = pvma->vm_next;
  }

  return NULL;
}

int __mm_swap_page(struct pcb_t *caller, addr_t vicfpn , addr_t swpfpn)
{

  __swap_cp_page(caller->krnl->mram, vicfpn, caller->krnl->active_mswp, swpfpn);
  return 0;

  /* ??????????????????????????????
      // Validate caller and required kernel memory structures
    if (!caller || !caller->mram || !caller->active_mswp)
        return -1;

    struct memphy_struct *mram = caller->krnl->mram;
    struct memphy_struct *mswp = caller->krnl->active_mswp;

      // Copy victim frame data from RAM to swap space
    for (addr_t offset = 0; offset < PAGING_PAGESZ; offset++) {
        BYTE data;
        if (MEMPHY_read(mram, vicfpn * PAGING_PAGESZ + offset, &data) < 0)
            return -1;
        if (MEMPHY_write(mswp, swpfpn * PAGING_PAGESZ + offset, data) < 0)
            return -1;
    }

      // Update page table entry to mark victim page as swapped out
    addr_t pgn = -1;
    for (addr_t i = 0; i < PAGING_MAX_PGN; i++) {
        uint32_t pte = pte_get_entry(caller, i);
        if ((pte & PAGING_PTE_PRESENT_MASK) && PAGING_PTE_FPN(pte) == vicfpn) {
            pgn = i;
            break;
        }
    }

    if (pgn == -1)
        return -1;

    if (pte_set_swap(caller, pgn, 0, swpfpn) < 0)
        return -1;

    return 0;
*/
}

/*get_vm_area_node - get vm area for a number of pages */
struct vm_rg_struct *get_vm_area_node_at_brk(struct pcb_t *caller, int vmaid, addr_t size, addr_t alignedsz)
{
  struct vm_rg_struct * newrg;
  /* FIX: Dùng caller->mm để tránh Race Condition với Loader */
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if (cur_vma == NULL) return NULL;

  newrg = malloc(sizeof(struct vm_rg_struct));
  newrg->rg_start = cur_vma->sbrk;
  newrg->rg_end = newrg->rg_start + size;

  return newrg;
}

/*validate_overlap_vm_area */
int validate_overlap_vm_area(struct pcb_t *caller, int vmaid, addr_t vmastart, addr_t vmaend)
{
  /* FIX: Dùng caller->mm */
  struct mm_struct *mm = caller->mm;
  if (mm == NULL) return -1;

  struct vm_area_struct *vma = mm->mmap;

  if (vmastart >= vmaend) return -1;
  if (vma == NULL) return -1;

  struct vm_area_struct *cur_area = get_vma_by_num(mm, vmaid);
  if (cur_area == NULL) return -1;

  while (vma != NULL)
  {
    if (vma != cur_area && OVERLAP(cur_area->vm_start, cur_area->vm_end, vma->vm_start, vma->vm_end))
    {
      return -1;
    }
    vma = vma->vm_next;
  }

  return 0;
}

/*inc_vma_limit - increase vm area limits to reserve space for new variable */
int inc_vma_limit(struct pcb_t *caller, int vmaid, addr_t inc_sz)
{
  struct vm_rg_struct * newrg = malloc(sizeof(struct vm_rg_struct));
  if(!newrg) return -1;
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  if(!cur_vma) {
      free(newrg);
      return -1;
  }
  /* TOTO with new address scheme, the size need tobe aligned 
   *      the raw inc_sz maybe not fit pagesize
   */ 
  addr_t inc_amt;
  int incnumpage;

  addr_t old_end = cur_vma->vm_end;

  #ifdef MM64
  incnumpage = (inc_sz + PAGING64_PAGESZ - 1) / PAGING64_PAGESZ;
  inc_amt = incnumpage * PAGING64_PAGESZ;
  #else
  inc_amt = PAGING_PAGE_ALIGNSZ(inc_sz);
  incnumpage = inc_amt / PAGING_PAGESZ;
  #endif

  addr_t new_end = cur_vma->vm_end + inc_amt;

  /* TODO Validate overlap of obtained region */
  if (validate_overlap_vm_area(caller, vmaid, old_end, new_end) < 0){
    free(newrg);
    return -1; /*Overlap and failed allocation */
  }
  /* TODO: Obtain the new vm area based on vmaid */
  cur_vma->vm_end = new_end;
  cur_vma->sbrk = new_end;

  newrg->rg_start = old_end;
  newrg->rg_end = new_end;
  newrg->rg_next = NULL;

 if (cur_vma->vm_freerg_list == NULL) {
        cur_vma->vm_freerg_list = newrg;
    } else {
        enlist_vm_rg_node(&cur_vma->vm_freerg_list, newrg);
    }

  //inc_limit_ret...
  /* The obtained vm area (only)
   * now will be alloc real ram region */

  if (vm_map_ram(caller, newrg->rg_start, newrg->rg_end, 
                   old_end, incnumpage , newrg) < 0)
  {
    //cur_vma->vm_end = old_end; //rollback
    //cur_vma->sbrk = old_end;
    return 0; /* ← SUCCESS! Virtual space is reserved */
  }
  /* Success: RAM mapped immediately */
  return 0;
}

