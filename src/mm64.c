/*
 * PAGING based Memory Management
 * Memory management unit mm/mm64.c
 */

#include "mm64.h"
#include <stdlib.h>
#include <stdio.h>
#include "os-cfg.h"

#if defined(MM64)

/* * init_pte - Initialize PTE entry 
 */
int init_pte(addr_t *pte,
             int pre,    // present
             addr_t fpn, // FPN
             int drt,    // dirty
             int swp,    // swap
             int swptyp, // swap type
             addr_t swpoff) // swap offset
{
  if (pre != 0) {
    if (swp == 0) { // Non swap ~ page online
      if (fpn == 0)
        return -1;  // Invalid setting

      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
    }
    else
    { // page swapped
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
      SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
    }
  }
  return 0;
}

/*
 * get_pd_from_address - Parse address to 5 page directory level
 */
int get_pd_from_address(addr_t addr, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
  *pgd = PAGING64_ADDR_PGD(addr); 
  *p4d = PAGING64_ADDR_P4D(addr); 
  *pud = PAGING64_ADDR_PUD(addr); 
  *pmd = PAGING64_ADDR_PMD(addr); 
  *pt  = PAGING64_ADDR_PT(addr);  
  return 0;
}

int get_pd_from_pagenum(addr_t pgn, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
  return get_pd_from_address(pgn << PAGING64_ADDR_PT_SHIFT, pgd, p4d, pud, pmd, pt);
}

/* Helper: walk_page_table */
static addr_t* walk_page_table(struct mm_struct *mm, addr_t pgn, int alloc) {
    addr_t pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;
    
    if (mm == NULL) return NULL;
    if (mm->pgd == NULL) return NULL;

    get_pd_from_pagenum(pgn, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);

    // --- Level 5: PGD ---
    addr_t *p4d_table = (addr_t *)mm->pgd[pgd_idx];
    if (p4d_table == NULL) {
        if (!alloc) return NULL;
        p4d_table = (addr_t *)calloc(512, sizeof(addr_t)); 
        mm->pgd[pgd_idx] = (addr_t)p4d_table; 
    }

    // --- Level 4: P4D ---
    addr_t *pud_table = (addr_t *)p4d_table[p4d_idx];
    if (pud_table == NULL) {
        if (!alloc) return NULL;
        pud_table = (addr_t *)calloc(512, sizeof(addr_t));
        p4d_table[p4d_idx] = (addr_t)pud_table;
    }

    // --- Level 3: PUD ---
    addr_t *pmd_table = (addr_t *)pud_table[pud_idx];
    if (pmd_table == NULL) {
        if (!alloc) return NULL;
        pmd_table = (addr_t *)calloc(512, sizeof(addr_t));
        pud_table[pud_idx] = (addr_t)pmd_table;
    }

    // --- Level 2: PMD ---
    addr_t *pt_table = (addr_t *)pmd_table[pmd_idx];
    if (pt_table == NULL) {
        if (!alloc) return NULL;
        pt_table = (addr_t *)calloc(512, sizeof(addr_t));
        pmd_table[pmd_idx] = (addr_t)pt_table;
    }

    // --- Level 1: PT ---
    return &pt_table[pt_idx];
}

/* pte_set_swap */
int pte_set_swap(struct pcb_t *caller, addr_t pgn, int swptyp, addr_t swpoff)
{
    addr_t *pte = walk_page_table(caller->mm, pgn, 1);
    if (!pte) return -1;

    SETBIT(*pte, PAGING_PTE_PRESENT_MASK); 
    SETBIT(*pte, PAGING_PTE_SWAPPED_MASK); 
    SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT); 
    SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
    return 0;
}

/* pte_set_fpn */
int pte_set_fpn(struct pcb_t *caller, addr_t pgn, addr_t fpn)
{
    addr_t *pte = walk_page_table(caller->mm, pgn, 1);
    if (!pte) return -1;

    SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
    CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
    SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
    return 0;
}

/* pte_get_entry */
uint32_t pte_get_entry(struct pcb_t *caller, addr_t pgn)
{
    addr_t *pte = walk_page_table(caller->mm, pgn, 0);
    if (!pte) return 0;
    return (uint32_t)*pte;
}

/*
 * vmap_page_range - map a range of page at aligned address
 */
addr_t vmap_page_range(struct pcb_t *caller, 
                    addr_t addr, 
                    int pgnum, 
                    struct framephy_struct *frames, 
                    struct vm_rg_struct *ret_rg)
{
    struct framephy_struct *fpit = frames;
    int pgit = 0;
    addr_t pgn;

    ret_rg->rg_start = addr;
    ret_rg->rg_end = addr + pgnum * PAGING64_PAGESZ;
    
    for(pgit = 0; pgit < pgnum; pgit++) {
        pgn = (addr + pgit * PAGING64_PAGESZ) >> PAGING64_ADDR_PT_SHIFT;

        if(fpit == NULL) break;

        pte_set_fpn(caller, pgn, fpit->fpn); 
        fpit = fpit->fp_next;
        
        enlist_pgn_node(&caller->mm->fifo_pgn, pgn);
    }
    return 0;
}

/* alloc_pages_range */
addr_t alloc_pages_range(struct pcb_t *caller, int req_pgnum, struct framephy_struct **frm_lst)
{
    int pgit;
    int fpn; 
    struct framephy_struct *head = NULL, *tail = NULL, *new_node;

    for (pgit = 0; pgit < req_pgnum; pgit++) {
        /* FIX: Dùng caller->krnl->mram thay vì caller->mram */
        if (MEMPHY_get_freefp(caller->krnl->mram, &fpn) == 0) {
            new_node = malloc(sizeof(struct framephy_struct));
            new_node->fpn = fpn;
            new_node->fp_next = NULL;

            if (head == NULL) { head = new_node; tail = new_node; } 
            else { tail->fp_next = new_node; tail = new_node; }
        } else {
             // Hết RAM -> Trả về mã lỗi đặc biệt
             return -3000; 
        }
    }
    *frm_lst = head;
    return 0;
}

/* vm_map_ram */
addr_t vm_map_ram(struct pcb_t *caller, addr_t astart, addr_t aend, addr_t mapstart, int incpgnum, struct vm_rg_struct *ret_rg)
{
  struct framephy_struct *frm_lst = NULL;
  addr_t ret_alloc;

  ret_alloc = alloc_pages_range(caller, incpgnum, &frm_lst);

  if (ret_alloc == (addr_t)-3000) return -1;

  vmap_page_range(caller, mapstart, incpgnum, frm_lst, ret_rg);
  return 0;
}

/* __swap_cp_page */
int __swap_cp_page(struct memphy_struct *mpsrc, addr_t srcfpn,
                   struct memphy_struct *mpdst, addr_t dstfpn)
{
  int cellidx;
  addr_t addrsrc, addrdst;
  for (cellidx = 0; cellidx < PAGING64_PAGESZ; cellidx++)
  {
    addrsrc = srcfpn * PAGING64_PAGESZ + cellidx;
    addrdst = dstfpn * PAGING64_PAGESZ + cellidx;
    BYTE data;
    MEMPHY_read(mpsrc, addrsrc, &data);
    MEMPHY_write(mpdst, addrdst, data);
  }
  return 0;
}

/*
 * init_mm
 */
int init_mm(struct mm_struct *mm, struct pcb_t *caller)
{
  struct vm_area_struct *vma0 = malloc(sizeof(struct vm_area_struct));

  mm->pgd = (addr_t*)calloc(512, sizeof(addr_t)); 

  vma0->vm_id = 0;
  vma0->vm_start = 0;
  vma0->vm_end = vma0->vm_start;
  vma0->sbrk = vma0->vm_start;
  
  struct vm_rg_struct *first_rg = init_vm_rg(vma0->vm_start, vma0->vm_end);
  enlist_vm_rg_node(&vma0->vm_freerg_list, first_rg);

  vma0->vm_next = NULL;
  vma0->vm_mm = mm; 
  mm->mmap = vma0;

  if (caller != NULL) {
      caller->mm = mm;
  }
  
  return 0;
}

struct vm_rg_struct *init_vm_rg(addr_t rg_start, addr_t rg_end)
{
  struct vm_rg_struct *rgnode = malloc(sizeof(struct vm_rg_struct));
  rgnode->rg_start = rg_start;
  rgnode->rg_end = rg_end;
  rgnode->rg_next = NULL;
  return rgnode;
}

int enlist_vm_rg_node(struct vm_rg_struct **rglist, struct vm_rg_struct *rgnode)
{
  rgnode->rg_next = *rglist;
  *rglist = rgnode;
  return 0;
}

int enlist_pgn_node(struct pgn_t **plist, addr_t pgn)
{
  struct pgn_t *pnode = malloc(sizeof(struct pgn_t));
  pnode->pgn = pgn;
  pnode->pg_next = *plist;
  *plist = pnode;
  return 0;
}

int print_list_fp(struct framephy_struct *ifp)
{
  struct framephy_struct *fp = ifp;
  printf("print_list_fp: ");
  if (fp == NULL) { printf("NULL list\n"); return -1;}
  printf("\n");
  while (fp != NULL)
  {
    printf("fp[%ld]\n", fp->fpn);
    fp = fp->fp_next;
  }
  printf("\n");
  return 0;
}

int print_list_rg(struct vm_rg_struct *irg)
{
  struct vm_rg_struct *rg = irg;
  printf("print_list_rg: ");
  if (rg == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (rg != NULL)
  {
    printf("rg[%ld->%ld]\n", irg->rg_start, irg->rg_end);
    rg = rg->rg_next;
  }
  printf("\n");
  return 0;
}

int print_list_vma(struct vm_area_struct *ivma)
{
  struct vm_area_struct *vma = ivma;
  printf("print_list_vma: ");
  if (vma == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (vma != NULL)
  {
    printf("va[%ld->%ld]\n", vma->vm_start, vma->vm_end);
    vma = vma->vm_next;
  }
  printf("\n");
  return 0;
}

int print_list_pgn(struct pgn_t *ip)
{
  printf("print_list_pgn: ");
  if (ip == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (ip != NULL)
  {
    printf("va[%ld]-\n", ip->pgn);
    ip = ip->pg_next;
  }
  printf("\n");
  return 0;
}

int print_pgtbl(struct pcb_t *caller, addr_t start, addr_t end)
{
  int pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;

  get_pd_from_address(start, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);

  struct mm_struct *mm = caller->mm;
  if (mm == NULL || mm->pgd == NULL) return -1;

  printf("print_pgtbl:\n");

  addr_t *p4d_tbl = (addr_t *)mm->pgd[pgd_idx];
  printf(" PDG=%016lx", (unsigned long)p4d_tbl); 

  if (p4d_tbl == NULL) { printf("\n"); return 0; }

  addr_t *pud_tbl = (addr_t *)p4d_tbl[p4d_idx];
  printf(" P4g=%016lx", (unsigned long)pud_tbl);

  if (pud_tbl == NULL) { printf("\n"); return 0; }

  addr_t *pmd_tbl = (addr_t *)pud_tbl[pud_idx];
  printf(" PUD=%016lx", (unsigned long)pmd_tbl);

  if (pmd_tbl == NULL) { printf("\n"); return 0; }

  addr_t *pt_tbl = (addr_t *)pmd_tbl[pmd_idx];
  printf(" PMD=%016lx\n", (unsigned long)pt_tbl);

  return 0;
}

int vmap_pgd_memset(struct pcb_t *caller, addr_t addr, int pgnum)
{
    int pgit;
    addr_t pgn;
    for(pgit = 0; pgit < pgnum; pgit++) {
        pgn = (addr + pgit * PAGING64_PAGESZ) >> PAGING64_ADDR_PT_SHIFT;
        walk_page_table(caller->mm, pgn, 1);
    }
    return 0;
}

#endif 