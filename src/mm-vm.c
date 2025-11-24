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

/* __mm_swap_page - swap wrapper */
int __mm_swap_page(struct pcb_t *caller, addr_t vicfpn , addr_t swpfpn)
{
    __swap_cp_page(caller->krnl->mram, vicfpn, caller->krnl->active_mswp, swpfpn);
    return 0;
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
  int inc_amt;
  int incnumpage;
  
  /* FIX: Dùng caller->mm */
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  int old_end;

  if (cur_vma == NULL) {
      free(newrg);
      return -1;
  }

  old_end = cur_vma->vm_end;

#ifdef MM64
  incnumpage = (inc_sz + PAGING64_PAGESZ - 1) / PAGING64_PAGESZ;
  inc_amt = incnumpage * PAGING64_PAGESZ;
#else
  inc_amt = PAGING_PAGE_ALIGNSZ(inc_sz);
  incnumpage = inc_amt / PAGING_PAGESZ;
#endif

  if (cur_vma->vm_next != NULL && old_end + inc_amt > cur_vma->vm_next->vm_start) {
    free(newrg);
    return -1; 
  }

  cur_vma->vm_end += inc_amt;
  cur_vma->sbrk += inc_amt;

  /* LAZY ALLOCATION:
   * Nếu map thất bại (do hết RAM), KHÔNG rollback.
   * Để process giữ vùng địa chỉ ảo đó, sau này truy cập sẽ swap.
   */
  if (vm_map_ram(caller, old_end, cur_vma->vm_end, 
                   old_end, incnumpage , newrg) < 0)
  {
      // printf("DEBUG: Map RAM failed (Lazy Alloc active) for PID %d\n", caller->pid);
      // Không rollback!
  }
  
  free(newrg);
  return 0;
}
