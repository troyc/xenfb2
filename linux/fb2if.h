/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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

#ifndef __FB2IF_H__
#define __FB2IF_H__

/* Out events (frontend -> backend) */

#define XENFB2_TYPE_MODE_REQUEST 1
#define XENFB2_TYPE_RESIZE 2

struct xenfb2_mode
{
    uint8_t type; /* XENFB2_TYPE_MODE_REQUEST || XENFB2_TYPE_RESIZE */

    unsigned int xres;
    unsigned int yres;
    unsigned int bpp;
    unsigned int offset;
};

#define XENFB2_TYPE_DIRTY_READY 3

struct xenfb2_dirty_ready
{
    uint8_t type; /* XENFB2_TYPE_DIRTY_READY */
};

#define XENFB2_OUT_EVENT_SIZE 40

union xenfb2_out_event
{
    uint8_t type;
    struct xenfb2_mode mode;
    struct xenfb2_dirty_ready dirty_ready;
    char pad[XENFB2_OUT_EVENT_SIZE];
};

/* In events (backend -> frontend) */

#define XENFB2_TYPE_MODE_REPLY 1

struct xenfb2_mode_rep
{
    uint8_t type; /* XENFB2_TYPE_MODE_REPLY */

    unsigned int pitch;
    int mode_ok;
};

#define XENFB2_TYPE_UPDATE_FB2M 2

struct xenfb2_update_fb2m
{
    uint8_t type; /* XENFB2_TYPE_UPDATE_FB2M */

    unsigned int start;
    unsigned int end; /* Inclusive */
};

#define XENFB2_TYPE_UPDATE_DIRTY  3

struct xenfb2_update_dirty
{
    uint8_t type; /* XENFB2_TYPE_UPDATE_DIRTY */
};

#define XENFB2_TYPE_FB_CACHING 4

struct xenfb2_fb_caching
{
    uint8_t type; /* XENFB2_TYPE_FB_CACHING */

    unsigned long cache_attr;
};

#define XENFB2_IN_EVENT_SIZE 40

union xenfb2_in_event
{
    uint8_t type;
    struct xenfb2_mode_rep mode_reply;
    struct xenfb2_update_fb2m update_fb2m;
    struct xenfb2_update_dirty update_dirty;
    struct xenfb2_fb_caching fb_caching;
    char pad[XENFB2_IN_EVENT_SIZE];
};

/* shared page */

#define XENFB2_IN_RING_SIZE 1024
#define XENFB2_IN_RING_LEN (XENFB2_IN_RING_SIZE / XENFB2_IN_EVENT_SIZE)
#define XENFB2_IN_RING_OFFS 1024
#define XENFB2_IN_RING(page) \
    ((union xenfb2_in_event *)((char *)(page) + XENFB2_IN_RING_OFFS))
#define XENFB2_IN_RING_REF(page, idx) \
    (XENFB2_IN_RING((page))[(idx) % XENFB2_IN_RING_LEN])

#define XENFB2_OUT_RING_SIZE 2048
#define XENFB2_OUT_RING_LEN (XENFB2_OUT_RING_SIZE / XENFB2_OUT_EVENT_SIZE)
#define XENFB2_OUT_RING_OFFS (XENFB2_IN_RING_OFFS + XENFB2_IN_RING_SIZE)
#define XENFB2_OUT_RING(page) \
    ((union xenfb2_out_event *)((char *)(page) + XENFB2_OUT_RING_OFFS))
#define XENFB2_OUT_RING_REF(page, idx) \
    (XENFB2_OUT_RING((page))[(idx) % XENFB2_OUT_RING_LEN])

struct xenfb2_page
{
  uint32_t in_cons, in_prod;
  uint32_t out_cons, out_prod;


  unsigned long     fb_size;
  unsigned long     fb2m[16];
  unsigned long     fb2m_nents;

  unsigned long     dirty_bitmap_page;
};

#endif /* __FB2IF_H__ */

