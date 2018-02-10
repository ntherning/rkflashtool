/* rkflashtool - for RockChip based devices.
 *
 * Copyright (C) 2010-2018 by Ivo van Poorten, Fukaumi Naoki, Guenter Knauf,
 *                            Ulrich Prinz, Steve Wilson, Sjoerd Simons,
 *                            Julien Chauveau, Ramon Steppat
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libusb.h>
#include <time.h>

/* hack to set binary mode for stdin / stdout on Windows */
#ifdef _WIN32
#include <fcntl.h>
int _CRT_fmode = _O_BINARY;
#endif

#include "version.h"
#include "rkcrc.h"
#include "rkflashtool.h"

static const struct t_pid {
    const uint16_t pid;
    const char name[8];
} pidtab[] = {
    { 0x262c, "RKNANOC"},
    { 0x281a, "RK2818"},
    { 0x290a, "RK2918"},
    { 0x292a, "RK2928"},
    { 0x292c, "RK3026"},
    { 0x300a, "RK3066"},
    { 0x300b, "RK3168"},
    { 0x301a, "RK3036"},
    { 0x310a, "RK3066B"},
    { 0x310b, "RK3188"},
    { 0x310c, "RK312X"}, // Both RK3126 and RK3128
    { 0x310d, "RK3126"},
    { 0x320a, "RK3288"},
    { 0x320b, "RK322X"}, // Both RK3228 and RK3229
    { 0x320c, "RK3328"},
    { 0x330a, "RK3368"},
    { 0x330c, "RK3399"},
    { 0, ""},
};

typedef struct {
    uint32_t flash_size;
    uint16_t block_size;
    uint8_t page_size;
    uint8_t ecc_bits;
    uint8_t access_time;
    uint8_t manufacturer_id;
    uint8_t chip_select;
} nand_info;

static const char* const manufacturer[] = {   /* NAND Manufacturers */
    "Samsung",
    "Toshiba",
    "Hynix",
    "Infineon",
    "Micron",
    "Renesas",
    "Intel",
    "UNKNOWN", /* Reserved */
    "SanDisk",
};

static uint8_t cmd[31], res[13], buf[RKFT_BLOCKSIZE];
static uint8_t ibuf[RKFT_IDB_BLOCKSIZE];
static libusb_context *c;
static libusb_device_handle *h = NULL;
static int tmp, send_endpoint_id = 2, offset = 0, size = 0;

static struct timespec ts;

static const char *const strings[2] = { "info", "fatal" };

static void disconnect_and_close_usb(void) {
    if (h) {
        libusb_release_interface(h, 0);
        libusb_close(h);
    }
    if (c) libusb_exit(c);
}

static void info_and_fatal(const int s, const int cr, char *f, ...) {
    va_list ap;
    va_start(ap,f);
    fprintf(stderr, "%srkflashtool: %s: ", cr ? "\r" : "", strings[s]);
    vfprintf(stderr, f, ap);
    va_end(ap);
    if (s) {
        disconnect_and_close_usb();
        exit(s);
    }
}

#define info(...)    info_and_fatal(0, 0, __VA_ARGS__)
#define infocr(...)  info_and_fatal(0, 1, __VA_ARGS__)
#define fatal(...)   info_and_fatal(1, 0, __VA_ARGS__)

static void usage(void) {
    fatal("usage:\n"
          "\trkflashtool b [reset_flag]      \treboot device\n\n"
          "\trkflashtool l <file             \tload DDR init (MASK ROM MODE)\n"
          "\trkflashtool L <file             \tload USB loader (MASK ROM MODE)\n\n"
          "\trkflashtool v                   \tread chip version\n"
          "\trkflashtool n                   \tread NAND flash info\n\n"
          "\trkflashtool i offset nsectors >outfile \tread IDBlocks\n"
          "\trkflashtool j offset nsectors <infile  \twrite IDBlocks\n\n"
          "\trkflashtool m offset nbytes   >outfile \tread SDRAM\n"
          "\trkflashtool M offset nbytes   <infile  \twrite SDRAM\n"
          "\trkflashtool B krnl_addr parm_addr      \texec SDRAM\n\n"
          "\trkflashtool r partname >outfile \tread flash partition by name\n"
          "\trkflashtool w partname <infile  \twrite flash partition by name\n"
          "\trkflashtool r offset nsectors >outfile \tread flash partition\n"
          "\trkflashtool w offset nsectors <infile  \twrite flash partition\n\n"
//          "\trkflashtool f                 >outfile \tread fuses\n"
//          "\trkflashtool g                 <infile  \twrite fuses\n"
          "\trkflashtool p >file             \tfetch parameters\n"
          "\trkflashtool P <file             \twrite parameters\n\n"
          "\trkflashtool e partname          \terase flash (fill with 0xff)\n"
          "\trkflashtool e offset nsectors   \terase flash (fill with 0xff)\n"
         );
}

static void send_exec(uint32_t krnl_addr, uint32_t parm_addr) {
    long int r = rand();

    memset(cmd, 0 , 31);
    memcpy(cmd, "USBC", 4);

    if (r)          SETBE32(cmd+4, r);
    if (krnl_addr)  SETBE32(cmd+17, krnl_addr);
    if (parm_addr)  SETBE32(cmd+22, parm_addr);
                    SETBE32(cmd+12, RKFT_CMD_EXECUTESDRAM);

    libusb_bulk_transfer(h, send_endpoint_id|LIBUSB_ENDPOINT_OUT, cmd, sizeof(cmd), &tmp, 0);
}

static void send_reset(uint8_t flag) {
    long int r = rand();

    memset(cmd, 0 , 31);
    memcpy(cmd, "USBC", 4);

    SETBE32(cmd+4, r);
    SETBE32(cmd+12, RKFT_CMD_RESETDEVICE);
    cmd[16] = flag;

    libusb_bulk_transfer(h, send_endpoint_id|LIBUSB_ENDPOINT_OUT, cmd, sizeof(cmd), &tmp, 0);
}

static void send_cmd(uint32_t command, uint32_t offset, uint16_t nsectors) {
    long int r = rand();

    memset(cmd, 0 , 31);
    memcpy(cmd, "USBC", 4);

    if (r)          SETBE32(cmd+4, r);
    if (offset)     SETBE32(cmd+17, offset);
    if (nsectors)   SETBE16(cmd+22, nsectors);
    if (command)    SETBE32(cmd+12, command);

    libusb_bulk_transfer(h, send_endpoint_id|LIBUSB_ENDPOINT_OUT, cmd, sizeof(cmd), &tmp, 0);
}

static void send_buf(unsigned int s) {
    libusb_bulk_transfer(h, send_endpoint_id|LIBUSB_ENDPOINT_OUT, buf, s, &tmp, 0);
}

static void recv_res(void) {
    libusb_bulk_transfer(h, 1|LIBUSB_ENDPOINT_IN, res, sizeof(res), &tmp, 0);
}

static void recv_buf(unsigned int s) {
    libusb_bulk_transfer(h, 1|LIBUSB_ENDPOINT_IN, buf, s, &tmp, 0);
}

/* Parse partition name and set offset and size accordingly */

static void parse_partition_name(char *partname) {
    char *mtdparts, *found, partexp[256];

    info("working with partition: %s\n", partname);

    /* Read parameters */
    offset = 0;
    send_cmd(RKFT_CMD_READLBA, offset, RKFT_OFF_INCR);
    recv_buf(RKFT_BLOCKSIZE);
    recv_res();

    size = GET32LE(buf+4);
    if (size < 0 || size > MAX_PARAM_LENGTH)
      fatal("invalid size of parameter block\n");
    info("size of parameter block: %i\n", size);

    if (!(mtdparts = strstr((const char *)buf+8, "mtdparts=")))
        fatal("'mtdparts' not found in command line\n");

    snprintf(partexp, sizeof(partexp), "(%s)", partname);
    if (!(found = strstr(mtdparts, partexp)))
        fatal("partition '%s' not found\n", partname);
    *found = 0;     /* cut string before (partition_name) */

    if (!(found = strrchr(mtdparts, '@')))
        fatal("bad syntax in mtdparts\n");

    offset = strtoul(found+1, NULL, 0);
    info("found offset: %#010x\n", offset);

    *found = 0;     /* cut string before @-sign */

    if ((found = strrchr(mtdparts, '-'))) {
        /* Read size from NAND info */
        send_cmd(RKFT_CMD_READFLASHINFO, 0, 0);
        recv_buf(512);
        recv_res();

        nand_info *nand = (nand_info *) buf;
        size = nand->flash_size - offset;

        info("partition extends up to the end of NAND\n");
        goto found_size;
    }

    if ((found = strrchr(mtdparts, ','))) {
        size = strtoul(found+1, NULL, 0);
        goto found_size;
    }

    if ((found = strrchr(mtdparts, ':'))) {
        size = strtoul(found+1, NULL, 0);
        goto found_size;
    }

    fatal("bad syntax for partition size.\n");

found_size:
    info("found size: %#010x\n", size);
}

#define NEXT do { argc--;argv++; } while(0)

int main(int argc, char **argv) {
    struct libusb_device_descriptor desc;
    struct libusb_config_descriptor *config;
    const struct t_pid *ppid = pidtab;
    ssize_t nr;
    uint16_t crc16;
    uint8_t flag = 0;
    char action;
    char *partname = NULL;

    info("rkflashtool v%d.%d\n", RKFLASHTOOL_VERSION_MAJOR,
                                 RKFLASHTOOL_VERSION_MINOR);

    NEXT; if (!argc) usage();

    action = **argv; NEXT;

    switch(action) {
    case 'b':
        if (argc > 1) usage();
        else if (argc == 1)
            flag = strtoul(argv[0], NULL, 0);
        break;
    case 'l':
    case 'L':
        if (argc) usage();
        break;
    case 'e':
    case 'r':
    case 'w':
        if (argc < 1 || argc > 2) usage();
        if (argc == 1) {
            partname = argv[0];
        } else {
            offset = strtoul(argv[0], NULL, 0);
            size   = strtoul(argv[1], NULL, 0);
        }
        break;
    case 'm':
    case 'M':
    case 'B':
    case 'i':
    case 'j':
        if (argc != 2) usage();
        offset = strtoul(argv[0], NULL, 0);
        size   = strtoul(argv[1], NULL, 0);
        break;
    case 'n':
    case 'v':
    case 'p':
    case 'P':
        if (argc) usage();
        offset = 0;
        size   = 1024;
        break;
    default:
        usage();
    }

    /* Initialize libusb */

    if (libusb_init(&c)) fatal("cannot init libusb\n");

    libusb_set_debug(c, 3);

    /* Detect connected RockChip device */

    while ( !h && ppid->pid) {
        h = libusb_open_device_with_vid_pid(c, 0x2207, ppid->pid);
        if (h) {
            info("Detected %s...\n", ppid->name);
            break;
        }
        ppid++;
    }
    if (!h) fatal("cannot open device\n");

    /* Connect to device */
    
    if (libusb_kernel_driver_active(h, 0) == 1) {
        info("kernel driver active\n");
        if (!libusb_detach_kernel_driver(h, 0))
            info("driver detached\n");
    }

    if (libusb_claim_interface(h, 0) < 0)
        fatal("cannot claim interface\n");
    info("interface claimed\n");

    if (libusb_get_device_descriptor(libusb_get_device(h), &desc) != 0)
        fatal("cannot get device descriptor\n");

    /* Get number of endpoints, to calculate the endpoint id for sending commands */

    if (libusb_get_config_descriptor(libusb_get_device(h), 0, &config) != 0)
        fatal("cannot get config descriptor\n");

    uint8_t num_endpoints = (uint8_t)config->interface[0].altsetting[0].bNumEndpoints;

    /* Search for the outgoing endpoint id */

    for(uint8_t i = 0; i < num_endpoints; i++) {
        const struct libusb_endpoint_descriptor *epdesc = &config->interface[0].altsetting[0].endpoint[i];

        if((epdesc->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_CONTROL) {
            if((epdesc->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
                send_endpoint_id = epdesc->bEndpointAddress & LIBUSB_ENDPOINT_ADDRESS_MASK;
            }
        }
    }

    if (desc.bcdUSB == 0x200)
        info("MASK ROM MODE\n");

    switch(action) {
    case 'l':
        info("load DDR init\n");
        crc16 = 0xffff;
        while ((nr = read(0, buf, 4096)) == 4096) {
            crc16 = rkcrc16(crc16, buf, nr);
            libusb_control_transfer(h, LIBUSB_REQUEST_TYPE_VENDOR, 12, 0, 1137, buf, nr, 0);
        }
        if (nr != -1) {
            crc16 = rkcrc16(crc16, buf, nr);
            buf[nr++] = crc16 >> 8;
            buf[nr++] = crc16 & 0xff;
            libusb_control_transfer(h, LIBUSB_REQUEST_TYPE_VENDOR, 12, 0, 1137, buf, nr, 0);
        }
        goto exit;
    case 'L':
        info("load USB loader\n");
        crc16 = 0xffff;
        while ((nr = read(0, buf, 4096)) == 4096) {
            crc16 = rkcrc16(crc16, buf, nr);
            libusb_control_transfer(h, LIBUSB_REQUEST_TYPE_VENDOR, 12, 0, 1138, buf, nr, 0);
        }
        if (nr != -1) {
            crc16 = rkcrc16(crc16, buf, nr);
            buf[nr++] = crc16 >> 8;
            buf[nr++] = crc16 & 0xff;
            libusb_control_transfer(h, LIBUSB_REQUEST_TYPE_VENDOR, 12, 0, 1138, buf, nr, 0);
        }
        goto exit;
    }

    /* Initialize bootloader interface */

    send_cmd(RKFT_CMD_TESTUNITREADY, 0, 0);
    recv_res();
    ts.tv_nsec = 20*1000*1000;
    while (nanosleep(&ts, &ts)) ;

    if (partname)
        parse_partition_name(partname);

    /* Check and execute command */

    switch(action) {
    case 'b':   /* Reboot device */
        info("rebooting device...\n");
        send_reset(flag);
        recv_res();
        break;
    case 'r':   /* Read FLASH */
        while (size > 0) {
            infocr("reading flash memory at offset 0x%08x", offset);

            send_cmd(RKFT_CMD_READLBA, offset, RKFT_OFF_INCR);
            recv_buf(RKFT_BLOCKSIZE);
            recv_res();

            if (write(1, buf, RKFT_BLOCKSIZE) <= 0)
                fatal("Write error! Disk full?\n");

            offset += RKFT_OFF_INCR;
            size   -= RKFT_OFF_INCR;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'w':   /* Write FLASH */
        while (size > 0) {
            infocr("writing flash memory at offset 0x%08x", offset);

            if (read(0, buf, RKFT_BLOCKSIZE) <= 0) {
                fprintf(stderr, "... Done!\n");
                info("premature end-of-file reached.\n");
                goto exit;
            }

            send_cmd(RKFT_CMD_WRITELBA, offset, RKFT_OFF_INCR);
            send_buf(RKFT_BLOCKSIZE);
            recv_res();

            offset += RKFT_OFF_INCR;
            size   -= RKFT_OFF_INCR;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'p':   /* Retreive parameters */
        {
            uint32_t *p = (uint32_t*)buf+1;

            info("reading parameters at offset 0x%08x\n", offset);

            send_cmd(RKFT_CMD_READLBA, offset, RKFT_OFF_INCR);
            recv_buf(RKFT_BLOCKSIZE);
            recv_res();

            /* Check size */
            size = *p;
            info("size:  0x%08x\n", size);
            if (size < 0 || size > MAX_PARAM_LENGTH)
                fatal("Bad parameter length!\n");

            /* Check CRC */
            uint32_t crc_buf = *(uint32_t *)(buf + 8 + size),
                     crc = 0;
            crc = rkcrc32(crc, buf + 8, size);
            if (crc_buf != crc)
              fatal("bad CRC! (%#x, should be %#x)\n", crc_buf, crc);

            if (write(1, &buf[8], size) <= 0)
                fatal("Write error! Disk full?\n");
        }
        break;
    case 'P':   /* Write parameters */
        {
            /* Header */
            strncpy((char *)buf, "PARM", 4);

            /* Content */
            int sizeRead;
            if ((sizeRead = read(0, buf + 8, RKFT_BLOCKSIZE - 8)) < 0) {
                info("read error: %s\n", strerror(errno));
                goto exit;
            }

            /* Length */
            *(uint32_t *)(buf + 4) = sizeRead;

            /* CRC */
            uint32_t crc = 0;
            crc = rkcrc32(crc, buf + 8, sizeRead);
            PUT32LE(buf + 8 + sizeRead, crc);

            /*
             * The parameter file is written at 8 different offsets:
             * 0x0000, 0x0400, 0x0800, 0x0C00, 0x1000, 0x1400, 0x1800, 0x1C00
             */

            for(offset = 0; offset < 0x2000; offset += 0x400) {
                infocr("writing flash memory at offset 0x%08x", offset);
                send_cmd(RKFT_CMD_WRITELBA, offset, RKFT_OFF_INCR);
                send_buf(RKFT_BLOCKSIZE);
                recv_res();
            }
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'm':   /* Read RAM */
        while (size > 0) {
            int sizeRead = size > RKFT_BLOCKSIZE ? RKFT_BLOCKSIZE : size;
            infocr("reading memory at offset 0x%08x size %x", offset, sizeRead);

            send_cmd(RKFT_CMD_READSDRAM, offset - SDRAM_BASE_ADDRESS, sizeRead);
            recv_buf(sizeRead);
            recv_res();

            if (write(1, buf, sizeRead) <= 0)
                fatal("Write error! Disk full?\n");

            offset += sizeRead;
            size -= sizeRead;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'M':   /* Write RAM */
        while (size > 0) {
            int sizeRead;
            if ((sizeRead = read(0, buf, RKFT_BLOCKSIZE)) <= 0) {
                info("premature end-of-file reached.\n");
                goto exit;
            }
            infocr("writing memory at offset 0x%08x size %x", offset, sizeRead);

            send_cmd(RKFT_CMD_WRITESDRAM, offset - SDRAM_BASE_ADDRESS, sizeRead);
            send_buf(sizeRead);
            recv_res();

            offset += sizeRead;
            size -= sizeRead;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'B':   /* Exec RAM */
        info("booting kernel...\n");
        send_exec(offset - SDRAM_BASE_ADDRESS, size - SDRAM_BASE_ADDRESS);
        recv_res();
        break;
    case 'i':   /* Read IDB */
        while (size > 0) {
            int sizeRead = size > RKFT_IDB_INCR ? RKFT_IDB_INCR : size;
            infocr("reading IDB flash memory at offset 0x%08x", offset);

            send_cmd(RKFT_CMD_READSECTOR, offset, sizeRead);
            recv_buf(RKFT_IDB_BLOCKSIZE * sizeRead);
            recv_res();

            if (write(1, buf, RKFT_IDB_BLOCKSIZE * sizeRead) <= 0)
                fatal("Write error! Disk full?\n");

            offset += sizeRead;
            size -= sizeRead;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'j':   /* write IDB */
        while (size > 0) {
            infocr("writing IDB flash memory at offset 0x%08x", offset);

            memset(ibuf, RKFT_IDB_BLOCKSIZE, 0xff);
            if (read(0, ibuf, RKFT_IDB_DATASIZE) <= 0) {
                fprintf(stderr, "... Done!\n");
                info("premature end-of-file reached.\n");
                goto exit;
            }

            send_cmd(RKFT_CMD_WRITESECTOR, offset, 1);
            libusb_bulk_transfer(h, 2|LIBUSB_ENDPOINT_OUT, ibuf, RKFT_IDB_BLOCKSIZE, &tmp, 0);
            recv_res();
            offset += 1;
            size -= 1;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'e':   /* Erase flash */
        memset(buf, 0xff, RKFT_BLOCKSIZE);
        while (size > 0) {
            infocr("erasing flash memory at offset 0x%08x", offset);

            send_cmd(RKFT_CMD_WRITELBA, offset, RKFT_OFF_INCR);
            send_buf(RKFT_BLOCKSIZE);
            recv_res();

            offset += RKFT_OFF_INCR;
            size   -= RKFT_OFF_INCR;
        }
        fprintf(stderr, "... Done!\n");
        break;
    case 'v':   /* Read Chip Version */
        send_cmd(RKFT_CMD_READCHIPINFO, 0, 0);
        recv_buf(16);
        recv_res();

        info("chip version: %c%c%c%c-%c%c%c%c.%c%c.%c%c-%c%c%c%c\n",
            buf[ 3], buf[ 2], buf[ 1], buf[ 0],
            buf[ 7], buf[ 6], buf[ 5], buf[ 4],
            buf[11], buf[10], buf[ 9], buf[ 8],
            buf[15], buf[14], buf[13], buf[12]);
        break;
    case 'n':   /* Read NAND Flash Info */
    {
        if(ppid->pid != 0x262c) {
            send_cmd(RKFT_CMD_READFLASHID, 0, 0);
            recv_buf(5);
            recv_res();

            info("Flash ID: %02x %02x %02x %02x %02x\n",
            buf[0], buf[1], buf[2], buf[3], buf[4]);
        }

        send_cmd(RKFT_CMD_READFLASHINFO, 0, 0);
        recv_buf(512);
        recv_res();

        nand_info *nand = (nand_info *) buf;
        uint8_t id = nand->manufacturer_id,
                cs = nand->chip_select;

        info("Flash Info:\n"
             "\tManufacturer: %s (%d)\n"
             "\tFlash Size: %dMB\n"
             "\tBlock Size: %dKB\n"
             "\tPage Size: %dKB\n"
             "\tECC Bits: %d\n"
             "\tAccess Time: %d\n"
             "\tFlash CS:%s%s%s%s\n",

             /* Manufacturer */
             id < MAX_NAND_ID ? manufacturer[id] : "Unknown",
             id,

             nand->flash_size >> 11, /* Flash Size */
             nand->block_size >> 1,  /* Block Size */
             nand->page_size  >> 1,  /* Page Size */
             nand->ecc_bits,         /* ECC Bits */
             nand->access_time,      /* Access Time */

             /* Flash CS */
             cs & 1 ? " <0>" : "",
             cs & 2 ? " <1>" : "",
             cs & 4 ? " <2>" : "",
             cs & 8 ? " <3>" : "");
    }
    default:
        break;
    }

exit:
    disconnect_and_close_usb();
    return 0;
}
