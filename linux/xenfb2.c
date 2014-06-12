/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/console.h>
#include <linux/freezer.h>
#include <xen/xenbus.h>
#include <linux/kthread.h>
#include <linux/fb.h>
#include <xen/interface/io/protocols.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <asm/xen/page.h>
#include <xen/events.h>
#else
#include <linux/mm.h>
#include <asm/page.h>
#include <xen/evtchn.h>
#include <xen/interface/domctl.h> /* For caching */
#endif

#include "fb2if.h"

#define MB_ (1024*1024)

#define XENFB2_DEFAULT_FB_SIZE (16 * MB_)
#define XENFB2_DEFAULT_XRES 1024
#define XENFB2_DEFAULT_YRES 768
#define XENFB2_DEFAULT_BPP 32

struct xenfb2_mapping
{
    struct list_head            link;
    struct vm_area_struct       *vma;
    struct xenfb2_info          *info;
    atomic_t                    refs;
};

struct xenfb2_modeinfo
{
    struct list_head            link;

    unsigned int                xres;
    unsigned int                yres;
    unsigned int                bpp;
    unsigned int                pitch;
};

struct xenfb2_fb_page
{
    struct page                 *page;
    unsigned long               orig_mfn;
};

struct xenfb2_info
{
    int                         irq;
    struct xenfb2_page          *shared_page;
    struct fb_info              *fb_info;

    int                         fb_npages;
    void                        *fb;
    struct xenfb2_fb_page       *fb_pages;
    int                         fb2m_npages;
    unsigned long               *fb2m;

    unsigned long               *dirty_bitmap;
    unsigned long               *shadow_bitmap;
#define BITMAP_LEN(info) \
    (((info)->fb_npages + BITS_PER_LONG - 1) / BITS_PER_LONG)

    struct list_head            mappings;
    struct mutex                mm_lock;
    unsigned long               cache_attr;

    wait_queue_head_t           thread_wq;
    struct task_struct          *kthread;
    unsigned long               thread_flags;

    wait_queue_head_t           checkvar_wait;
    struct mutex                checkvar_lock;
    struct xenfb2_mode_rep      *mode_rep;

    struct list_head            modes;
    spinlock_t                  mode_lock;
    struct xenfb2_modeinfo      *default_mode;

    unsigned long               fb_size;

    struct xenbus_device        *xbdev;
};

static int xenfb2_remove(struct xenbus_device *dev);
static void xenfb2_init_shared_page(struct xenfb2_info *info,
                                    struct fb_info * fb_info);

static struct xenfb2_modeinfo *xenfb2_mode_lookup(struct xenfb2_info *info,
                                              unsigned int xres,
                                              unsigned int yres,
                                              unsigned int bpp)
{
    unsigned long flags;
    struct xenfb2_modeinfo *iter, *mode = NULL;

    spin_lock_irqsave(&info->mode_lock, flags);

    list_for_each_entry(iter, &info->modes, link) {
        if (iter->xres == xres && iter->yres == yres &&
            iter->bpp == bpp) {
            mode = iter;
            break;
        }
    }

    spin_unlock_irqrestore(&info->mode_lock, flags);
    return mode;
}

static struct xenfb2_modeinfo *xenfb2_mode_add(struct xenfb2_info *info,
                                           unsigned int xres,
                                           unsigned int yres,
                                           unsigned int bpp,
                                           unsigned int pitch)
{
    unsigned long flags;
    struct xenfb2_modeinfo *iter, *mode = NULL;

    spin_lock_irqsave(&info->mode_lock, flags);

    list_for_each_entry(iter, &info->modes, link) {
        if (iter->xres == xres && iter->yres == yres &&
            iter->bpp == bpp) {
            mode = iter;
            break;
        }
    }

    if (mode == NULL) {
        mode = kzalloc(sizeof (*mode), GFP_KERNEL);
        if (mode == NULL)
            goto unlock;
        mode->xres = xres;
        mode->yres = yres;
        mode->bpp = bpp;

        list_add(&mode->link, &info->modes);
    }

    mode->pitch = pitch;

unlock:
    spin_unlock_irqrestore(&info->mode_lock, flags);
    return mode;
}

static void xenfb2_modelist_purge(struct xenfb2_info *info)
{
    unsigned long flags;
    struct list_head *iter, *tmp;

    spin_lock_irqsave(&info->mode_lock, flags);

    list_for_each_safe(iter, tmp, &info->modes) {
        list_del(iter);
        kfree(list_entry(iter, struct xenfb2_modeinfo, link));
    }

    spin_unlock_irqrestore(&info->mode_lock, flags);
}

static void xenfb2_send_event(struct xenfb2_info *info,
		              union xenfb2_out_event *event)
{
    __u32 prod;

    prod = info->shared_page->out_prod;
    /* caller ensures !xenfb_queue_full() */
    mb();			/* ensure ring space available */
    XENFB2_OUT_RING_REF(info->shared_page, prod) = *event;
    wmb();			/* ensure ring contents visible */
    info->shared_page->out_prod = prod + 1;

    notify_remote_via_irq(info->irq);
}

static void xenfb2_vm_open(struct vm_area_struct *vma)
{
    struct xenfb2_mapping *map = vma->vm_private_data;
    atomic_inc(&map->refs);
}

static void xenfb2_vm_close(struct vm_area_struct *vma)
{
    struct xenfb2_mapping *map = vma->vm_private_data;
    struct xenfb2_info *info = map->info;

    mutex_lock(&info->mm_lock);
    if (atomic_dec_and_test(&map->refs)) {
        list_del(&map->link);
        kfree(map);
    }
    mutex_unlock(&info->mm_lock);
}

static int xenfb2_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct xenfb2_mapping *map = vma->vm_private_data;
    struct xenfb2_info *info = map->info;
    int pgnr = ((long)vmf->virtual_address - vma->vm_start) >> PAGE_SHIFT;
    struct page *page;

    if (pgnr >= info->fb_npages)
        return VM_FAULT_SIGBUS;

    page = info->fb_pages[pgnr].page;
    get_page(page);

    vmf->page = page;

    /*
     * Julian & Eric:
     *
     * Xorg may issue read accesses before actually writing on the
     * framebuffer. Thus, subsequent write accesses on the same pages
     * may not be trapped and reported properly in the dirty bitmap because
     * the page is already mapped.
     *
     * We fix that by marking the page as dirty even for read accesses.
     */
#if 0
    if (vmf->flags & FAULT_FLAG_WRITE) {
        set_bit(pgnr % BITS_PER_LONG,
                &info->shadow_bitmap[pgnr / BITS_PER_LONG]);
    }
#endif
    set_bit(pgnr, &info->shadow_bitmap[0]);

    return VM_FAULT_MINOR;
}

static struct vm_operations_struct xenfb2_vm_ops = {
    .open   = xenfb2_vm_open,
    .close  = xenfb2_vm_close,
    .fault  = xenfb2_vm_fault,
};

static int xenfb2_mmap(struct fb_info *fb_info, struct vm_area_struct *vma)
{
    struct xenfb2_info *info = fb_info->par;
    struct xenfb2_mapping *map;
    int npages;

    if (!(vma->vm_flags & VM_WRITE))
            return -EINVAL;
    if (!(vma->vm_flags & VM_SHARED))
            return -EINVAL;
    if (vma->vm_pgoff != 0)
            return -EINVAL;

    npages = (vma->vm_end - vma->vm_start + PAGE_SIZE - 1) >> PAGE_SHIFT;
    if (npages > info->fb_npages)
        return -EINVAL;

    map = kzalloc(sizeof(*map), GFP_KERNEL);
    if (map == NULL)
        return -ENOMEM;

    map->vma = vma;
    map->info = info;
    atomic_set(&map->refs, 1);

    mutex_lock(&info->mm_lock);
    list_add(&map->link, &info->mappings);
    mutex_unlock(&info->mm_lock);

    vma->vm_ops = &xenfb2_vm_ops;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0))
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#else
    vma->vm_flags |= (VM_DONTEXPAND | VM_RESERVED);
#endif
    vma->vm_private_data = map;

    vma->vm_page_prot = __pgprot((pgprot_val(vma->vm_page_prot) &
                                  ~_PAGE_CACHE_MASK) | info->cache_attr);

    return 0;
}

static int xenfb2_check_var(struct fb_var_screeninfo *var,
                            struct fb_info *fb_info)
{
    struct xenfb2_info *info = fb_info->par;
    struct xenfb2_mode req;
    int rc;

    req.type = XENFB2_TYPE_MODE_REQUEST;
    req.xres = var->xres;
    req.yres = var->yres;
    req.bpp = var->bits_per_pixel;

    rc = mutex_lock_interruptible(&info->checkvar_lock);
    if (rc != 0)
        return -EINTR;

    /* Send event */
    xenfb2_send_event(info, (union xenfb2_out_event *)&req);

    /* Wait for reply */
    /* we get lots of signal interruptions on X start/restart, resulting in mode changes being lost because X
     * doesn't restart the check_var call if we give ERESTARTSYS. Hence loop until the response from dom0(surfman) is received
     * no matter what*/

    do {
        rc = wait_event_interruptible(info->checkvar_wait, info->mode_rep);
    } while (rc != 0);

    rc = -EINVAL;
    if (info->mode_rep && info->mode_rep->mode_ok)
    {
        xenfb2_mode_add(info, var->xres, var->yres, var->bits_per_pixel,
                        info->mode_rep->pitch);

        kfree(info->mode_rep);
        info->mode_rep = NULL;

        var->xres_virtual = var->xres;
        var->yres_virtual = var->yres;

        rc = 0;
    }

    mutex_unlock(&info->checkvar_lock);
    return rc;
}

static int xenfb2_set_par(struct fb_info *fb_info)
{
    struct xenfb2_info *info = fb_info->par;
    struct xenfb2_modeinfo *mode;
    struct xenfb2_mode req;

    mode = xenfb2_mode_lookup(info,
                              fb_info->var.xres_virtual,
                              fb_info->var.yres_virtual,
                              fb_info->var.bits_per_pixel);

    if (!mode)
        return -EINVAL;

    fb_info->fix.line_length = mode->pitch;

    /* Send resize event */
    req.type = XENFB2_TYPE_RESIZE;
    req.xres = fb_info->var.xres_virtual;
    req.yres = fb_info->var.yres_virtual;
    req.bpp = fb_info->var.bits_per_pixel;
    req.offset = mode->pitch * fb_info->var.xoffset
        + ((mode->bpp / 8) * fb_info->var.yoffset);
    xenfb2_send_event(info, (union xenfb2_out_event *)&req);

    return 0;
}

static int xenfb2_setcolreg(unsigned regno, unsigned red, unsigned green,
			    unsigned blue, unsigned transp,
			    struct fb_info *info)
{
    u32 v;

    if (regno > info->cmap.len)
        return 1;

    red >>= (16 - info->var.red.length);
    green >>= (16 - info->var.green.length);
    blue >>= (16 - info->var.blue.length);

    v = (red << info->var.red.offset) |
        (green << info->var.green.offset) |
        (blue << info->var.blue.offset);

    switch (info->var.bits_per_pixel) {
    case 16:
    case 24:
    case 32:
	((u32 *)info->pseudo_palette)[regno] = v;
	break;
    }

    return 0;
}

static void xenfb2_fillrect(struct fb_info *p, const struct fb_fillrect *rect)
{
    cfb_fillrect(p, rect);
}

static void xenfb2_imageblit(struct fb_info *p, const struct fb_image *image)
{
    cfb_imageblit(p, image);
}

static void xenfb2_copyarea(struct fb_info *p, const struct fb_copyarea *area)
{
    cfb_copyarea(p, area);
}

static int xenfb2_release(struct fb_info *fb_info, int user)
{
    struct xenfb2_info *info = fb_info->par;
    unsigned int i;

    if (info && info->fb) {
        memset(info->fb, 0, info->fb_size);

        /* Update dirty bitmap */
        for (i = 0; i < BITMAP_LEN(info); i++)
            info->shadow_bitmap[i] = ~0;
    }
    return 0;
}

static struct fb_ops xenfb2_fb_ops = {
    .owner          = THIS_MODULE,
    .fb_setcolreg   = xenfb2_setcolreg,
    .fb_fillrect    = xenfb2_fillrect,
    .fb_copyarea    = xenfb2_copyarea,
    .fb_imageblit   = xenfb2_imageblit,
    .fb_mmap        = xenfb2_mmap,
    .fb_check_var   = xenfb2_check_var,
    .fb_set_par     = xenfb2_set_par,
    .fb_release     = xenfb2_release,
};

static int xenfb2_thread(void *data)
{
    struct xenfb2_info *info = (void *)data;
    struct xenfb2_mapping *map;
    unsigned long i;

    wait_event_interruptible(info->thread_wq, kthread_should_stop() ||
                             test_and_clear_bit(0, &info->thread_flags));
    try_to_freeze();

    while (!kthread_should_stop()) {
        union xenfb2_out_event evt;

        mutex_lock(&info->mm_lock);
        list_for_each_entry(map, &info->mappings, link) {
            struct vm_area_struct *vma = map->vma;

            zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
                           NULL);
            vma->vm_page_prot = __pgprot((pgprot_val(vma->vm_page_prot) &
                                          ~_PAGE_CACHE_MASK) | info->cache_attr);
        }
        mutex_unlock(&info->mm_lock);

        /* Atomically copy shadow_bitmap to dirty bitmap and clear it */
        for (i = 0; i < BITMAP_LEN(info); i++)
            info->dirty_bitmap[i] = xchg(&info->shadow_bitmap[i], 0);

        /* Send event */
        evt.type = XENFB2_TYPE_DIRTY_READY;
        xenfb2_send_event(info, (union xenfb2_out_event *)&evt);

        wait_event_interruptible(info->thread_wq, kthread_should_stop() ||
                                 test_and_clear_bit(0, &info->thread_flags));
        try_to_freeze();
    }

    return 0;
}

static void xenfb2_update_fb2m(struct xenfb2_info *info, unsigned int start,
                               unsigned int end)
{
    unsigned int pagenr;

    start = min_t(unsigned int, start, info->fb_size >> PAGE_SHIFT);
    end = min_t(unsigned int, end, (info->fb_size - 1) >> PAGE_SHIFT);

    for (pagenr = start; pagenr <= end; pagenr++)
    {
        unsigned long pfn = page_to_pfn(info->fb_pages[pagenr].page);
        unsigned long mfn = info->fb2m[pagenr];

        set_phys_to_machine(pfn, mfn);
    }

    set_bit(0, &info->thread_flags);
    wake_up_interruptible(&info->thread_wq);
}

static void xenfb2_update_dirty(struct xenfb2_info *info)
{
    set_bit(0, &info->thread_flags);
    wake_up_interruptible(&info->thread_wq);
}

static void xenfb2_fb_caching(struct xenfb2_info *info,
                              unsigned long cache_attr)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
    switch (cache_attr) {
        case XEN_DOMCTL_MEM_CACHEATTR_UC:
            info->cache_attr = _PAGE_CACHE_UC;
            break;
        case XEN_DOMCTL_MEM_CACHEATTR_WC:
            info->cache_attr = _PAGE_CACHE_WC;
                break;
        case XEN_DOMCTL_MEM_CACHEATTR_WT:
            info->cache_attr = _PAGE_CACHE_WT;
                break;
        case XEN_DOMCTL_MEM_CACHEATTR_WP:
            info->cache_attr = _PAGE_CACHE_WP;
                break;
        case XEN_DOMCTL_MEM_CACHEATTR_WB:
            info->cache_attr = _PAGE_CACHE_WB;
                break;
        case XEN_DOMCTL_MEM_CACHEATTR_UCM:
            info->cache_attr = _PAGE_CACHE_UC_MINUS;
                break;
	default:
            return;
    }
#else
    printk("xenfb2: xenfb2_fb_caching has been called. This is not supposed to happen\n");
    printk("xenfb2: Please report this to surfman/xenfb2 developpers.\n");
#endif

    set_bit(0, &info->thread_flags);
    wake_up_interruptible(&info->thread_wq);
}

static irqreturn_t xenfb2_event_handler(int rq, void *priv)
{
    struct xenfb2_info *info = priv;
    struct xenfb2_page *page = info->shared_page;
    __u32 cons, prod;

    prod = page->in_prod;
    if (prod == page->in_cons)
        return IRQ_HANDLED;
    rmb(); /* ensure we see ring contents up to prod */

    for (cons = page->in_cons; cons != prod; cons++) {
        union xenfb2_in_event *event;
        event = &XENFB2_IN_RING_REF(page, cons);

        switch (event->type) {
        case XENFB2_TYPE_MODE_REPLY:
            WARN_ON(info->mode_rep);
            info->mode_rep = kmalloc(sizeof (struct xenfb2_mode_rep), GFP_KERNEL);
            *info->mode_rep = event->mode_reply;
            wake_up_interruptible(&info->checkvar_wait);
            break;
        case XENFB2_TYPE_UPDATE_FB2M:
            xenfb2_update_fb2m(info, event->update_fb2m.start, event->update_fb2m.end);
            break;
        case XENFB2_TYPE_UPDATE_DIRTY:
            info->cache_attr = _PAGE_CACHE_WB;
            xenfb2_update_dirty(info);
            break;
        case XENFB2_TYPE_FB_CACHING:
            xenfb2_fb_caching(info, event->fb_caching.cache_attr);
            break;
        default:
            break;
        }
    }
    mb(); /* ensure we got ring contents */
    page->in_cons = cons;
    notify_remote_via_irq(info->irq);

    return IRQ_HANDLED;
}


static void xenfb2_disconnect_backend(struct xenfb2_info *info)
{
    if (info->irq >= 0)
        unbind_from_irqhandler(info->irq, info);
    info->irq = -1;
}

static void
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinit
#endif
xenfb2_make_preferred_console(void)
{
    struct console *c;

    if (console_set_on_cmdline)
        return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
    console_lock();
#else
    acquire_console_sem();
#endif
    for (c = console_drivers; c; c = c->next) {
        if (!strcmp(c->name, "tty") && c->index == 0)
            break;
    }
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
    console_unlock();
#else
    release_console_sem();
#endif
    if (c) {
        unregister_console(c);
        c->flags |= CON_CONSDEV;
        c->flags &= ~CON_PRINTBUFFER; /* don't print again */
        register_console(c);
    }
}

static int xenfb2_connect_backend(struct xenbus_device *dev,
                                  struct xenfb2_info *info)
{
    int ret;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    int evtchn, irq;
#endif
    struct xenbus_transaction xbt;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    ret = xenbus_alloc_evtchn(dev, &evtchn);
    if (ret)
        return ret;

    irq = bind_evtchn_to_irqhandler(evtchn, xenfb2_event_handler,
                                    0, "xenfb2", info);
    if (irq < 0) {
        xenbus_free_evtchn(dev, evtchn);
        xenbus_dev_fatal(dev, ret, "bind_evtchn_to_irqhandler");
        return irq;
    }
#else
    ret = bind_listening_port_to_irqhandler(dev->otherend_id, xenfb2_event_handler,
                                            0, "xenfb2", info);
    if (ret < 0) {
        xenbus_dev_fatal(dev, ret, "bind_listening_port_to_irqhandler");
        return ret;
    }

    info->irq = ret;
#endif

again:
    ret = xenbus_transaction_start(&xbt);
    if (ret) {
        xenbus_dev_fatal(dev, ret, "starting transaction");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
        goto unbind_irq;
#else
        return ret;
#endif
    }
    ret = xenbus_printf(xbt, dev->nodename, "page-ref", "%lu",
                        virt_to_mfn(info->shared_page));
    if (ret)
        goto error_xenbus;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    ret = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
                        evtchn);
#else
     ret = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
                        irq_to_evtchn_port(info->irq));
#endif
    if (ret)
        goto error_xenbus;
    ret = xenbus_printf(xbt, dev->nodename, "protocol", "%s",
                        XEN_IO_PROTO_ABI_NATIVE);
    if (ret)
        goto error_xenbus;
    ret = xenbus_transaction_end(xbt, 0);
    if (ret) {
        if (ret == -EAGAIN)
            goto again;
        xenbus_dev_fatal(dev, ret, "completing transaction");
        return ret;
    }

    xenbus_switch_state(dev, XenbusStateInitialised);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    info->irq = irq;
#endif
    return 0;

error_xenbus:
    xenbus_transaction_end(xbt, 1);
    xenbus_dev_fatal(dev, ret, "writing xenstore");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
unbind_irq:
    unbind_from_irqhandler(irq, info);
#endif
    return ret;
}

static void xenfb2_backend_read_params(struct xenbus_device *dev,
                                       struct xenfb2_info *info)
{
    int rc;
    unsigned int xres;
    unsigned int yres;
    unsigned int bpp;
    unsigned int pitch;

    rc = xenbus_scanf(XBT_NIL, dev->otherend, "default-xres", "%d", &xres);
    if (rc < 0)
        xres = XENFB2_DEFAULT_XRES;

    rc = xenbus_scanf(XBT_NIL, dev->otherend, "default-yres", "%d", &yres);
    if (rc < 0)
        yres = XENFB2_DEFAULT_YRES;

    rc = xenbus_scanf(XBT_NIL, dev->otherend, "default-bpp", "%d", &bpp);
    if (rc < 0)
        bpp = XENFB2_DEFAULT_BPP;

    rc = xenbus_scanf(XBT_NIL, dev->otherend, "default-pitch", "%d", &pitch);
    if (rc < 0)
        pitch = xres * (bpp / 8);

    rc = xenbus_scanf(XBT_NIL, dev->otherend, "videoram", "%lud", &info->fb_size);
    if (rc < 0)
        info->fb_size = XENFB2_DEFAULT_FB_SIZE;

    /* Readjust videoram if too small for resolution */
    info->fb_size = max_t(unsigned long, info->fb_size, pitch * yres);

    info->default_mode = xenfb2_mode_add(info, xres, yres, bpp, pitch);
}

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinit
#endif
xenfb2_probe(struct xenbus_device *dev,
	     const struct xenbus_device_id *id)
{
    struct xenfb2_info *info;
    struct fb_info *fb_info;
    int ret = 0;
    int i;

    info = kzalloc(sizeof (*info), GFP_KERNEL);
    if (!info) {
        xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
        return -ENOMEM;
    }

    dev_set_drvdata(&dev->dev, info);
    info->xbdev = dev;
    info->irq = -1;
    mutex_init(&info->mm_lock);
    INIT_LIST_HEAD(&info->mappings);
    init_waitqueue_head(&info->checkvar_wait);
    mutex_init(&info->checkvar_lock);
    info->mode_rep = NULL;
    INIT_LIST_HEAD(&info->modes);
    spin_lock_init(&info->mode_lock);

    info->thread_flags = 0;
    init_waitqueue_head(&info->thread_wq);
    info->kthread = kthread_run(xenfb2_thread, info, "xenfb2 thread");

    xenfb2_backend_read_params(dev, info);

    info->fb = vmalloc(info->fb_size);
    if (!info->fb)
        goto fail_nomem;
    memset(info->fb, 0, info->fb_size);

    info->fb_npages = (info->fb_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    info->fb_pages = kmalloc(sizeof (struct xenfb2_fb_page) * info->fb_npages,
                             GFP_KERNEL);
    if (!info->fb_pages)
        goto fail_nomem;

    /* Shouldn't take more than 8 pages (order 3) */
    info->fb2m_npages = (info->fb_npages * sizeof (unsigned long *) +
                         PAGE_SIZE - 1) >> PAGE_SHIFT;
    info->fb2m = vmalloc(info->fb_npages * sizeof (unsigned long *));
    if (!info->fb2m)
        goto fail_nomem;

    /* Shouldn't take more than 1 page */
    info->dirty_bitmap = vmalloc(BITMAP_LEN(info) * sizeof (unsigned long));
    if (!info->dirty_bitmap)
        goto fail_nomem;
    info->shadow_bitmap = kmalloc(BITMAP_LEN(info) * sizeof (unsigned long),
                                  GFP_KERNEL);
    if (!info->shadow_bitmap)
        goto fail_nomem;

    for (i = 0; i < BITMAP_LEN(info); i++)
        info->shadow_bitmap[i] = ~0;

    info->shared_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!info->shared_page)
        goto fail_nomem;

    info->cache_attr = _PAGE_CACHE_WC;

    fb_info = framebuffer_alloc(sizeof(u32) * 256, NULL);
    if (!fb_info)
        goto fail_nomem;
    fb_info->pseudo_palette = fb_info->par;
    fb_info->par = info;

    fb_info->fbops = &xenfb2_fb_ops;
    fb_info->var.xres_virtual = fb_info->var.xres = info->default_mode->xres;
    fb_info->var.yres_virtual = fb_info->var.yres = info->default_mode->yres;
    fb_info->var.bits_per_pixel = info->default_mode->bpp;

    fb_info->var.red = (struct fb_bitfield){16, 8, 0};
    fb_info->var.green = (struct fb_bitfield){8, 8, 0};
    fb_info->var.blue = (struct fb_bitfield){0, 8, 0};

    fb_info->var.activate = FB_ACTIVATE_NOW;
    fb_info->var.height = -1;
    fb_info->var.width = -1;
    fb_info->var.vmode = FB_VMODE_NONINTERLACED;

    fb_info->fix.visual = FB_VISUAL_TRUECOLOR;
    fb_info->fix.line_length = info->default_mode->pitch;
    fb_info->fix.smem_start = 0;
    fb_info->fix.smem_len = info->fb_size;
    strcpy(fb_info->fix.id, "xen");
    fb_info->fix.type = FB_TYPE_PACKED_PIXELS;
    fb_info->fix.accel = FB_ACCEL_NONE;

    fb_info->flags = FBINFO_FLAG_DEFAULT;

    ret = fb_alloc_cmap(&fb_info->cmap, 256, 0);
    if (ret < 0) {
        framebuffer_release(fb_info);
        xenbus_dev_fatal(dev, ret, "fb_alloc_cmap");
        goto fail;
    }

    xenfb2_init_shared_page(info, fb_info);

    ret = xenfb2_connect_backend(dev, info);
    if (ret < 0)
        goto fail;

    ret = register_framebuffer(fb_info);
    if (ret) {
        fb_dealloc_cmap(&info->fb_info->cmap);
        framebuffer_release(fb_info);
        xenbus_dev_fatal(dev, ret, "register_framebuffer");
        goto fail;
    }
    info->fb_info = fb_info;
    xenfb2_make_preferred_console();

    return 0;

fail_nomem:
    ret = -ENOMEM;
    xenbus_dev_fatal(dev, ret, "allocating device memory");
fail:
    xenfb2_remove(dev);
    return ret;
}

static int xenfb2_resume(struct xenbus_device *dev)
{
    struct xenfb2_info *info = dev_get_drvdata(&dev->dev);

    xenfb2_disconnect_backend(info);
    xenfb2_init_shared_page(info, info->fb_info);
    return xenfb2_connect_backend(dev, info);
}

static int xenfb2_remove(struct xenbus_device *dev)
{
    struct xenfb2_info *info = dev_get_drvdata(&dev->dev);

    xenfb2_modelist_purge(info);

    xenfb2_disconnect_backend(info);
    if (info->fb_info) {
        unregister_framebuffer(info->fb_info);
        fb_dealloc_cmap(&info->fb_info->cmap);
        framebuffer_release(info->fb_info);
    }
    if (info->shared_page)
        free_page((unsigned long)info->shared_page);
    if (info->fb2m)
        vfree(info->fb2m);
    if (info->fb_pages)
        kfree(info->fb_pages);
    if (info->fb)
        vfree(info->fb);
    if (info->dirty_bitmap)
        vfree(info->dirty_bitmap);
    if (info->shadow_bitmap)
        kfree(info->shadow_bitmap);
    if (info->kthread)
        kthread_stop(info->kthread);

    kfree(info);

    /* Et voila. */

    return 0;
}

static unsigned long vmalloc_to_mfn(void *p)
{
    return pfn_to_mfn(page_to_pfn(vmalloc_to_page(p)));
}

static void xenfb2_init_shared_page(struct xenfb2_info *info,
                                    struct fb_info * fb_info)
{
    struct xenfb2_page *page = info->shared_page;
    int i;

    for (i = 0; i < info->fb_npages; i++) {
        info->fb_pages[i].page = vmalloc_to_page((char *)info->fb + i * PAGE_SIZE);
        info->fb_pages[i].orig_mfn = info->fb2m[i] =
            pfn_to_mfn(page_to_pfn(info->fb_pages[i].page));
    }

    page->in_cons = page->in_prod = 0;
    page->out_cons = page->out_prod = 0;

    page->fb_size = info->fb_size;
    page->fb2m_nents = info->fb_npages;

    for (i = 0; i < info->fb2m_npages; i++) {
        page->fb2m[i] = vmalloc_to_mfn((char *)info->fb2m + i * PAGE_SIZE);
    }

    page->dirty_bitmap_page = vmalloc_to_mfn((char *)info->dirty_bitmap);
}

static void xenfb2_backend_changed(struct xenbus_device *dev,
                                   enum xenbus_state backend_state)
{
    struct xenfb2_info *info = dev_get_drvdata(&dev->dev);

    switch (backend_state) {
    case XenbusStateInitialising:
    case XenbusStateInitialised:
    case XenbusStateReconfiguring:
    case XenbusStateReconfigured:
    case XenbusStateUnknown:
    case XenbusStateClosed:
        break;

    case XenbusStateInitWait:
    InitWait:
        xenbus_switch_state(dev, XenbusStateConnected);
        break;

    case XenbusStateConnected:
        /*
         * Work around xenbus race condition: If backend goes
         * through InitWait to Connected fast enough, we can
         * get Connected twice here.
         */
        if (dev->state != XenbusStateConnected)
                goto InitWait; /* no InitWait seen yet, fudge it */

        /* Re-send framebuffer geometry */
        if (info && info->fb_info)
            xenfb2_set_par(info->fb_info);

        /* Reset FB2M */
        if (info) {
            unsigned int i;

            for (i = 0; i < info->fb_npages; i++) {
                unsigned long pfn = page_to_pfn(info->fb_pages[i].page);
                unsigned long mfn = info->fb_pages[i].orig_mfn;

                info->fb2m[i] = mfn;
                set_phys_to_machine(pfn, mfn);
            }

            set_bit(0, &info->thread_flags);
            wake_up_interruptible(&info->thread_wq);
        }

        break;
    case XenbusStateClosing:
        // FIXME is this safe in any dev->state?
        xenbus_frontend_closed(dev);
        break;
    }
}

static const struct xenbus_device_id xenfb2_ids[] = {
    { "vfb" },
    { "" }
};
MODULE_ALIAS("xen:vfb");

static struct xenbus_driver xenfb2_driver = {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0))
    .driver.name = "vfb",
    .driver.owner = THIS_MODULE,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    .name = "vfb",
    .owner = THIS_MODULE,
#endif
    .ids = xenfb2_ids,
    .probe = xenfb2_probe,
    .remove = xenfb2_remove,
    .resume = xenfb2_resume,
    .otherend_changed = xenfb2_backend_changed,
};

static int __init xenfb2_init(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    if (!xen_pv_domain())
#else
    if (!is_running_on_xen())
#endif
        return -ENODEV;

    /* Nothing to do if running in dom0. */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
    if (xen_initial_domain())
#else
    if (is_initial_xendomain())
#endif
	return -ENODEV;

    return xenbus_register_frontend(&xenfb2_driver);
}

static void __exit xenfb2_cleanup(void)
{
    xenbus_unregister_driver(&xenfb2_driver);
}

module_init(xenfb2_init);
module_exit(xenfb2_cleanup);

MODULE_DESCRIPTION("Xen virtual framebuffer device frontend");
MODULE_LICENSE("GPL");
