## 启动 ServiceManager 进程
通过Media服务的添加发现，Media服务是通过binder驱动访问了ServiceManager进程将Media服务交给ServiceManager去管理，那么ServiceManager是用来管理所有服务的
```c
IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");
```
\frameworks\native\cmds\servicemanager\service_manager.c</br>
进程启动进入main函数
```c
int main(int argc, char **argv)
{
    struct binder_state *bs;
    
    // 打开binder驱动
    bs = binder_open(128*1024);
   ...
    //成为上下文管理者
    if (binder_become_context_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }


     // selinux 权限是否使能
    selinux_enabled = is_selinux_enabled();
    sehandle = selinux_android_service_context_handle();
    selinux_status_open(true);

    if (selinux_enabled > 0) {
        if (sehandle == NULL) {
             // 无法获取 sehandle
            abort();
        }

        if (getcon(&service_manager_context) != 0) {
           // 法获取 sehandle
            abort();
        }
    }

   ...

   // 进入无限循环，处理 client 端发来的请求 
    binder_loop(bs, svcmgr_handler);

    return 0;
}

```
主要就是 </br>
1.打开binder</br>
2.成为服务的管理者</br>
3.进入loop循环，等待client端发来请求并处理请求</br></br>


binder_open
```c

struct binder_state
{
    // dev/binder 的文件描述符
    int fd; 
    // 指向 mmap 的内存地址
    void *mapped; 
    // 分配的内存大小，默认为128KB
    size_t mapsize; 
};

struct binder_state *binder_open(size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;
    // 申请一块128k的内存
    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    // 打开binder驱动文件 O_RDWR：可读写
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        goto fail_open;
    }

    // 判断一下版本
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        goto fail_open;
    }

   //  128k 字节的内存空间
    bs->mapsize = mapsize;
    // mmap映射到虚拟内存
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}
```

注册成为服务的管理者
```c
int binder_become_context_manager(struct binder_state *bs)
{
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}
```
loop
```c
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

   // 将 BC_ENTER_LOOPER 写入驱动，告诉驱动当前进程进入循环
    readbuf[0] = BC_ENTER_LOOPER;
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;
        
        // 不断的循环等待读取 binder 驱动的数据
        // 向驱动层去读数据，没有数据会进入等待，当别的进程往binder里面写数据时，会唤醒这个等待
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }
        
        // 解析读取到的数据
        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}
```
binder_write
```c
int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;
    // 代表写入数据大小，大小是 len
    bwr.write_size = len;
    bwr.write_consumed = 0;
    // LOOP的指令BC_ENTER_LOOPER
    bwr.write_buffer = (uintptr_t) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}
```
分析binder_parse先回顾一下，Media服务往数据区写入的指令BC_TRANSACTION</br>
写入到binder_transaction_data结构体中
```c
status_t IPCThreadState::transact(int32_t handle,
                                  uint32_t code, const Parcel& data,
                                  Parcel* reply, uint32_t flags)
{
    status_t err = data.errorCheck();
    // 没有error，写数据
    if (err == NO_ERROR) {
        err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL);
    }
    ...
    return err;
}
```
binder_parse驱动会修改值为BR_TRANSACTION
```c
// ptr 是读取数据的地址，是 bwr.read_buffer
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uintptr_t ptr, size_t size, binder_handler func)
{
    int r = 1;
    uintptr_t end = ptr + (uintptr_t) size;

    while (ptr < end) {
        // 先取指令
        uint32_t cmd = *(uint32_t *) ptr;
        // 数据接在指令后面，将指针移动到指令尾巴处
        ptr += sizeof(uint32_t);
        switch(cmd) {
        // 无操作退出循环
        case BR_NOOP:
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
            ptr += sizeof(struct binder_ptr_cookie);
            break;
            
        case BR_TRANSACTION: {
            // 解析读到的数据指令
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            ...
            binder_dump_txn(txn);
            
            if (func) {
                unsigned rdata[256/4];
                struct binder_io msg;
                struct binder_io reply;
                int res;
                // 初始化一个答复数据reply
                bio_init(&reply, rdata, sizeof(rdata), 4);
                //  从 txn 解析出 msg 信息
                bio_init_from_txn(&msg, txn);
                // 回调到fun也就是 binder_loop(bs, svcmgr_handler)传的svcmgr_handler
                res = func(bs, txn, &msg, &reply);
                // 向驱动层答复
                binder_send_reply(bs, &reply, txn->data.ptr.buffer, res);
            }
            ptr += sizeof(*txn);
            break;
        }
        case BR_REPLY: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                /* todo FREE BUFFER */
            }
            ptr += sizeof(*txn);
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (struct binder_death *)(uintptr_t) *(binder_uintptr_t *)ptr;
            ptr += sizeof(binder_uintptr_t);
            // binder挂了
            death->func(bs, death->ptr);
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            ALOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}
```

初始化和取Message，主要就是操作指针
```c
void bio_init(struct binder_io *bio, void *data,
              size_t maxdata, size_t maxoffs)
{
    size_t n = maxoffs * sizeof(size_t);

    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    bio->data = bio->data0 = (char *) data + n;
    bio->offs = bio->offs0 = data;
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

void bio_init_from_txn(struct binder_io *bio, struct binder_transaction_data *txn)
{
    bio->data = bio->data0 = (char *)(intptr_t)txn->data.ptr.buffer;
    bio->offs = bio->offs0 = (binder_size_t *)(intptr_t)txn->data.ptr.offsets;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offsets_size / sizeof(size_t);
    bio->flags = BIO_F_SHARED;
}
```
先看几个常量
```c
enum {
FIRST_CALL_TRANSACTION  = 0x00000001,
LAST_CALL_TRANSACTION   = 0x00ffffff,
PING_TRANSACTION        = B_PACK_CHARS('_','P','N','G'),
DUMP_TRANSACTION        = B_PACK_CHARS('_','D','M','P'),
INTERFACE_TRANSACTION   = B_PACK_CHARS('_', 'N', 'T', 'F'),
SYSPROPS_TRANSACTION    = B_PACK_CHARS('_', 'S', 'P', 'R'),
// Corresponds to TF_ONE_WAY -- an asynchronous call.
FLAG_ONEWAY             = 0x00000001
}


int GET_SERVICE_TRANSACTION = IBinder.FIRST_CALL_TRANSACTION(1);
int CHECK_SERVICE_TRANSACTION = IBinder.FIRST_CALL_TRANSACTION+1(2);
int ADD_SERVICE_TRANSACTION = IBinder.FIRST_CALL_TRANSACTION+2(3);
```
```c
enum {
    /* Must match definitions in IBinder.h and IServiceManager.h */
    PING_TRANSACTION  = B_PACK_CHARS('_','P','N','G'),
    SVC_MGR_GET_SERVICE = 1,
    SVC_MGR_CHECK_SERVICE,
    SVC_MGR_ADD_SERVICE,// 这里的值也是3
    SVC_MGR_LIST_SERVICES,
};

```


查看回调的处理</br>
svcmgr_handler主要处理message
```c
int svcmgr_handler(struct binder_state *bs,
                   struct binder_transaction_data *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;
    uint16_t *s;
    size_t len;
    uint32_t handle;
    uint32_t strict_policy;
    int allow_isolated;
    
    // 判断是不是找ServiceManager
    if (txn->target.ptr != BINDER_SERVICE_MANAGER)
        return -1;
    
    // 是不是ping的，Media服务是发一个ping的消息
    if (txn->code == PING_TRANSACTION)
        return 0;

    .....
    
    // 判断Code的命令
    // Medie发的是ADD_SERVICE_TRANSACTION，猜一下是ADD_SERVICE
    // ADD_SERVICE_TRANSACTION由常量查询到是3
    // 看一下SVC_MGR_ADD_SERVICE，值也是三，Media服务发过来的code值就是用来添加服务，让SeviceManager来管理的
    switch(txn->code) {
    
    // 查询检测Service
    case SVC_MGR_GET_SERVICE:
    case SVC_MGR_CHECK_SERVICE:
        // 获取服务的名称
        s = bio_get_string16(msg, &len);
        if (s == NULL) {
            return -1;
        }
        // 服务的handle值
        handle = do_find_service(bs, s, len, txn->sender_euid, txn->sender_pid);
        if (!handle)
            break;
        // 写入回复
        bio_put_ref(reply, handle);
        return 0;
    
    // 添加Service
    case SVC_MGR_ADD_SERVICE:
        // 获取服务的名称
        s = bio_get_string16(msg, &len);
        if (s == NULL) {
            return -1;
        }
        
        // 服务的handle值
        handle = bio_get_ref(msg);
        //添加到服务列表
        if (do_add_service(bs, s, len, handle, txn->sender_euid,
            allow_isolated, txn->sender_pid))
            return -1;
        break;

    ...
    }
    ...
    bio_put_uint32(reply, 0);
    return 0;
}

```
看一下怎么找的服务的handle</br>
do_find_service
```c
uint32_t do_find_service(struct binder_state *bs, const uint16_t *s, size_t len, uid_t uid, pid_t spid)
{

    // 根据名称查找服务信息
    struct svcinfo *si = find_svc(s, len);
    
    // 没找到，或找到的handle是0
    if (!si || !si->handle) {
        return 0;
    }
    
    ...
    return si->handle;
}
```
find_svc
```c
struct svcinfo *find_svc(const uint16_t *s16, size_t len)
{
    struct svcinfo *si;
    // 遍历链表找到之后 返回回去
    for (si = svclist; si; si = si->next) {
        if ((len == si->len) &&
            !memcmp(s16, si->name, len * sizeof(uint16_t))) {
            return si;
        }
    }
    return NULL;
}

struct svcinfo
{
    struct svcinfo *next;
    uint32_t handle;
    struct binder_death death;
    int allow_isolated;
    size_t len;
    uint16_t name[0];
};
```

看一下添加服务</br>
do_add_service
```c
int do_add_service(struct binder_state *bs,
                   const uint16_t *s, size_t len,
                   uint32_t handle, uid_t uid, int allow_isolated,
                   pid_t spid)
{
    struct svcinfo *si;

 
    // 没查到，查到了没数据，或数据超出大小 都失败
    if (!handle || (len == 0) || (len > 127))
        return -1;
    
    //检查权限 
    if (!svc_can_register(s, len, spid)) {
        return -1;
    }
    
    // 检索服务
    si = find_svc(s, len);
    if (si) {
        // 查到了，有handle值
        if (si->handle) {
            // 释放调之前添加的服务
            svcinfo_death(bs, si);
        }
        // 重新赋值handle
        si->handle = handle;
    } else {
        // 没有查到，先申请新的一块内存，用来存放这个服务的信息
        si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t));
        if (!si) {
            return -1;
        }
        // 赋值handler（Media服务的Handle）
        si->handle = handle;
        // 赋值长度
        si->len = len;
        // 赋值名称
        memcpy(si->name, s, (len + 1) * sizeof(uint16_t));
        si->name[len] = '\0';
        si->death.func = (void*) svcinfo_death;
        si->death.ptr = si;
        si->allow_isolated = allow_isolated;
        
        //保存服务形成链表
        si->next = svclist;
        svclist = si;
    }

    //往binder驱动层写一个BC_ACQUIRE的指令，handle为目标
    binder_acquire(bs, handle);
   // 往binder驱动层写一个BC_REQUEST_DEATH_NOTIFICATION 命令的信息，通过 ioctl 发送，主要用于清理内存等收尾工作
    binder_link_to_death(bs, handle, &si->death);
    return 0;
}
```



![大致流程](https://github.com/TF27674569/Other-Data/blob/master/image/service_manager_add.png)</br>

![包装的结构](https://github.com/TF27674569/Other-Data/blob/master/image/Binder_Data.png)</br>


