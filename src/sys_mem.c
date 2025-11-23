/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

#include "os-mm.h"
#include "syscall.h"
#include "libmem.h"
#include "queue.h"
#include <stdlib.h>
#include <stdio.h>
#ifdef MM64
#include "mm64.h"
#else
#include "mm.h"
#endif

//typedef char BYTE;

/* Helper function to find PCB by PID in a queue */
struct pcb_t *find_proc_in_queue(struct queue_t *q, uint32_t pid) {
    if (q == NULL) return NULL;
    for (int i = 0; i < q->size; i++) {
        if (q->proc[i]->pid == pid) {
            return q->proc[i];
        }
    }
    return NULL;
}

int __sys_memmap(struct krnl_t *krnl, uint32_t pid, struct sc_regs* regs)
{
   int memop = regs->a1;
   BYTE value;
   struct pcb_t *caller = NULL;

   /* * TODO 1: Tìm Process Caller
    * Thay vì malloc một dummy process, ta phải tìm process thực sự đang chạy.
    * Process gọi syscall thường nằm trong running_list.
    */
   
   // Tìm trong running_list trước (nơi chứa các process đang chạy trên CPU)
   caller = find_proc_in_queue(krnl->running_list, pid);

   // Nếu không thấy (trường hợp hy hữu), tìm trong ready_queue
   if (caller == NULL) {
       caller = find_proc_in_queue(krnl->ready_queue, pid);
   }

   // Nếu vẫn không tìm thấy PID hợp lệ, trả về lỗi
   if (caller == NULL) {
       printf("Error: Cannot find process with PID %d to exec sys_memmap\n", pid);
       return -1;
   }

   /* Dispatch các thao tác bộ nhớ dựa trên opcode (regs->a1) */
   switch (memop) {
   case SYSMEM_MAP_OP:
            /* Gán/Khởi tạo bảng trang (thường dùng cho test MM64) 
             * a2: address, a3: page number
             */
			vmap_pgd_memset(caller, regs->a2, regs->a3);
            break;

   case SYSMEM_INC_OP:
            /* Tăng giới hạn bộ nhớ (sbrk) 
             * a2: inc_sz (kích thước tăng thêm)
             */
            inc_vma_limit(caller, regs->a2, regs->a3);
            break;

   case SYSMEM_SWP_OP:
             /* Swap page (dùng cho test page replacement) */
            __mm_swap_page(caller, regs->a2, regs->a3);
            break;

   case SYSMEM_IO_READ:
            /* Đọc 1 byte từ bộ nhớ vật lý 
             * a2: Address, a3: Value (output)
             */
            // caller->mram (nếu nằm trong PCB) hoặc caller->krnl->mram
            // dùng mram của kernel gắn vào caller
            if (caller->mram != NULL) {
                MEMPHY_read(caller->mram, regs->a2, &value);
            } else {
                // Fallback nếu PCB chưa gán mram, dùng mram toàn cục của kernel
                MEMPHY_read(krnl->mram, regs->a2, &value);
            }
            
            // Trả giá trị đọc được về thanh ghi a3 để user process nhận được
            regs->a3 = (uint32_t)value;
            break;

   case SYSMEM_IO_WRITE:
            /* Ghi 1 byte vào bộ nhớ vật lý 
             * a2: Address, a3: Value (cần ghi)
             */
            if (caller->mram != NULL) {
                MEMPHY_write(caller->mram, regs->a2, (BYTE)regs->a3);
            } else {
                MEMPHY_write(krnl->mram, regs->a2, (BYTE)regs->a3);
            }
            break;

   default:
            printf("Memop code: %d\n", memop);
            return -1;
   }
   
   return 0;
}