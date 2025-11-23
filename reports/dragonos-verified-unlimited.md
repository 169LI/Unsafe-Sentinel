# VulnFusion 安全分析报告

融合 Rudra 与 SafeDrop 的高级漏洞检测

## 分析摘要

- **分析文件总数：** 975
- **代码行数：** 196920
- **发现漏洞数：** 10
- **分析时长：** 15
- **unsafe 块数：** 2250

### 按严重程度统计

| 严重程度 | 数量 |
|----------|-------|
| Critical | 9 |
| High | 1 |

### 按类型统计

| 类型 | 数量 |
|------|-------|
| drop-panic | 9 |
| uninitialized-read | 1 |

## 漏洞详情

### Critical（共 9 条）

#### 漏洞 #1：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\bpf\prog\mod.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
mod util;
mod verifier;

use super::Result;
use crate::bpf::map::BpfMap;
use crate::bpf::prog::util::{BpfProgMeta, BpfProgVerifierInfo};
use crate::bpf::prog::verifier::BpfProgVerifier;
use crate::filesystem::vfs::file::{File, FileMode};
use crate::filesystem::vfs::syscall::ModeType;
use crate::filesystem::vfs::{FilePrivateData, FileSystem, FileType, IndexNode, Metadata};
use crate::include::bindings::linux_bpf::bpf_attr;
use crate::libs::spinlock::SpinLockGuard;
use crate::process::ProcessManager;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use system_error::SystemError;

#[derive(Debug)]
pub struct BpfProg {
    meta: BpfProgMeta,
    raw_file_ptr: Vec<usize>,
}

impl BpfProg {
    pub fn new(meta: BpfProgMeta) -> Self {
        Self {
            meta,
            raw_file_ptr: Vec::new(),
        }
    }

    pub fn insns(&self) -> &[u8] {
        &self.meta.insns
    }

    pub fn insns_mut(&mut self) -> &mut [u8] {
        &mut self.meta.insns
    }

    pub fn insert_map(&mut self, map_ptr: usize) {
        self.raw_file_ptr.push(map_ptr);
    }
}

impl IndexNode for BpfProg {
    fn open(&self, _data: SpinLockGuard<FilePrivateData>, _mode: &FileMode) -> Result<()> {
        Ok(())
    }
    fn close(&self, _data: SpinLockGuard<FilePrivateData>) -> Result<()> {
        Ok(())
    }
    fn read_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &mut [u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        Err(SystemError::ENOSYS)
    }

    fn write_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &[u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        Err(SystemError::ENOSYS)
    }

    fn metadata(&self) -> Result<Metadata> {
        let meta = Metadata {
            mode: ModeType::from_bits_truncate(0o755),
            file_type: FileType::File,
            ..Default::default()
        };
        Ok(meta)
    }

    fn resize(&self, _len: usize) -> Result<()> {
        Ok(())
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        panic!("BpfProg does not have a filesystem")
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(SystemError::ENOSYS)
    }

    fn absolute_path(&self) -> core::result::Result<String, SystemError> {
        Ok(String::from("BPF Program"))
    }
}

impl Drop for BpfProg {
    fn drop(&mut self) {
        unsafe {
            for ptr in self.raw_file_ptr.iter() {
                let file = Arc::from_raw(*ptr as *const u8 as *const BpfMap);
                drop(file)
            }
        }
    }
}
/// Load a BPF program into the kernel.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/syscall/BPF_PROG_LOAD/
pub fn bpf_prog_load(attr: &bpf_attr) -> Result<usize> {
    let args = BpfProgMeta::try_from(attr)?;
    // info!("bpf_prog_load: {:#?}", args);
    let log_info = BpfProgVerifierInfo::from(attr);
    let prog = BpfProg::new(args);
    let fd_table = ProcessManager::current_pcb().fd_table();
    let prog = BpfProgVerifier::new(prog, log_info.log_level, &mut []).verify(&fd_table)?;
    let file = File::new(Arc::new(prog), FileMode::O_RDWR)?;
    let fd = fd_table.write().alloc_fd(file, None).map(|x| x as usize)?;
    Ok(fd)
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #2：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\driver\net\virtio_net.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use core::{
    any::Any,
    cell::UnsafeCell,
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
};

use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use log::{debug, error};
use smoltcp::{iface, phy, wire};
use unified_init::macros::unified_init;
use virtio_drivers::device::net::VirtIONet;

use super::{Iface, NetDeivceState, NetDeviceCommonData, Operstate};
use crate::{
    arch::rand::rand,
    driver::{
        base::{
            class::Class,
            device::{
                bus::Bus,
                driver::{Driver, DriverCommonData},
                Device, DeviceCommonData, DeviceId, DeviceType, IdTable,
            },
            kobject::{KObjType, KObject, KObjectCommonData, KObjectState, LockedKObjectState},
            kset::KSet,
        },
        net::{
            napi::{napi_schedule, NapiStruct},
            register_netdevice,
            types::InterfaceFlags,
        },
        virtio::{
            irq::virtio_irq_manager,
            sysfs::{virtio_bus, virtio_device_manager, virtio_driver_manager},
            transport::VirtIOTransport,
            virtio_impl::HalImpl,
            VirtIODevice, VirtIODeviceIndex, VirtIODriver, VirtIODriverCommonData, VirtioDeviceId,
            VIRTIO_VENDOR_ID,
        },
    },
    exception::{irqdesc::IrqReturn, IrqNumber},
    filesystem::{kernfs::KernFSInode, sysfs::AttributeGroup},
    init::initcall::INITCALL_POSTCORE,
    libs::{
        rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard},
        spinlock::{SpinLock, SpinLockGuard},
    },
    net::generate_iface_id,
    process::namespace::net_namespace::INIT_NET_NAMESPACE,
    time::Instant,
};
use system_error::SystemError;

static mut VIRTIO_NET_DRIVER: Option<Arc<VirtIONetDriver>> = None;

const VIRTIO_NET_BASENAME: &str = "virtio_net";

#[inline(always)]
#[allow(dead_code)]
fn virtio_net_driver() -> Arc<VirtIONetDriver> {
    unsafe { VIRTIO_NET_DRIVER.as_ref().unwrap().clone() }
}

/// virtio net device
#[cast_to([sync] VirtIODevice)]
#[cast_to([sync] Device)]
pub struct VirtIONetDevice {
    dev_id: Arc<DeviceId>,
    inner: SpinLock<InnerVirtIONetDevice>,
    locked_kobj_state: LockedKObjectState,

    // 指向对应的interface
    iface_ref: RwLock<Weak<VirtioInterface>>,
}

impl Debug for VirtIONetDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIONetDevice")
            .field("dev_id", &self.dev_id.id())
            .finish()
    }
}

unsafe impl Send for VirtIONetDevice {}
unsafe impl Sync for VirtIONetDevice {}

struct InnerVirtIONetDevice {
    device_inner: VirtIONicDeviceInner,
    name: Option<String>,
    virtio_index: Option<VirtIODeviceIndex>,
    kobj_common: KObjectCommonData,
    device_common: DeviceCommonData,
}

impl Debug for InnerVirtIONetDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InnerVirtIONetDevice").finish()
    }
}

impl VirtIONetDevice {
    pub fn new(transport: VirtIOTransport, dev_id: Arc<DeviceId>) -> Option<Arc<Self>> {
        // 设置中断
        if let Err(err) = transport.setup_irq(dev_id.clone()) {
            error!("VirtIONetDevice '{dev_id:?}' setup_irq failed: {:?}", err);
            return None;
        }

        let driver_net: VirtIONet<HalImpl, VirtIOTransport, 2> =
            match VirtIONet::<HalImpl, VirtIOTransport, 2>::new(transport, 4096) {
                Ok(net) => net,
                Err(_) => {
                    error!("VirtIONet init failed");
                    return None;
                }
            };
        let mac = wire::EthernetAddress::from_bytes(&driver_net.mac_address());
        debug!("VirtIONetDevice mac: {:?}", mac);
        let device_inner = VirtIONicDeviceInner::new(driver_net);
        device_inner.inner.lock_irqsave().enable_interrupts();
        let dev = Arc::new(Self {
            dev_id,
            inner: SpinLock::new(InnerVirtIONetDevice {
                device_inner,
                name: None,
                virtio_index: None,
                kobj_common: KObjectCommonData::default(),
                device_common: DeviceCommonData::default(),
            }),
            locked_kobj_state: LockedKObjectState::default(),
            iface_ref: RwLock::new(Weak::new()),
        });

        // dev.set_driver(Some(Arc::downgrade(&virtio_net_driver()) as Weak<dyn Driver>));

        return Some(dev);
    }

    fn inner(&self) -> SpinLockGuard<'_, InnerVirtIONetDevice> {
        return self.inner.lock();
    }

    pub fn set_iface(&self, iface: &Arc<VirtioInterface>) {
        *self.iface_ref.write() = Arc::downgrade(iface);
    }

    pub fn iface(&self) -> Option<Arc<VirtioInterface>> {
        self.iface_ref.read().upgrade()
    }
}

impl KObject for VirtIONetDevice {
    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn set_inode(&self, inode: Option<Arc<KernFSInode>>) {
        self.inner().kobj_common.kern_inode = inode;
    }

    fn inode(&self) -> Option<Arc<KernFSInode>> {
        self.inner().kobj_common.kern_inode.clone()
    }

    fn parent(&self) -> Option<Weak<dyn KObject>> {
        self.inner().kobj_common.parent.clone()
    }

    fn set_parent(&self, parent: Option<Weak<dyn KObject>>) {
        self.inner().kobj_common.parent = parent;
    }

    fn kset(&self) -> Option<Arc<KSet>> {
        self.inner().kobj_common.kset.clone()
    }

    fn set_kset(&self, kset: Option<Arc<KSet>>) {
        self.inner().kobj_common.kset = kset;
    }

    fn kobj_type(&self) -> Option<&'static dyn KObjType> {
        self.inner().kobj_common.kobj_type
    }

    fn set_kobj_type(&self, ktype: Option<&'static dyn KObjType>) {
        self.inner().kobj_common.kobj_type = ktype;
    }

    fn name(&self) -> String {
        self.device_name()
    }

    fn set_name(&self, _name: String) {
        // do nothing
    }

    fn kobj_state(&self) -> RwLockReadGuard<'_, KObjectState> {
        self.locked_kobj_state.read()
    }

    fn kobj_state_mut(&self) -> RwLockWriteGuard<'_, KObjectState> {
        self.locked_kobj_state.write()
    }

    fn set_kobj_state(&self, state: KObjectState) {
        *self.locked_kobj_state.write() = state;
    }
}

impl Device for VirtIONetDevice {
    fn dev_type(&self) -> DeviceType {
        DeviceType::Net
    }

    fn id_table(&self) -> IdTable {
        IdTable::new(VIRTIO_NET_BASENAME.to_string(), None)
    }

    fn bus(&self) -> Option<Weak<dyn Bus>> {
        self.inner().device_common.bus.clone()
    }

    fn set_bus(&self, bus: Option<Weak<dyn Bus>>) {
        self.inner().device_common.bus = bus;
    }

    fn class(&self) -> Option<Arc<dyn Class>> {
        let mut guard = self.inner();
        let r = guard.device_common.class.clone()?.upgrade();
        if r.is_none() {
            guard.device_common.class = None;
        }

        return r;
    }

    fn set_class(&self, class: Option<Weak<dyn Class>>) {
        self.inner().device_common.class = class;
    }

    fn driver(&self) -> Option<Arc<dyn Driver>> {
        let r = self.inner().device_common.driver.clone()?.upgrade();
        if r.is_none() {
            self.inner().device_common.driver = None;
        }

        return r;
    }

    fn set_driver(&self, driver: Option<Weak<dyn Driver>>) {
        self.inner().device_common.driver = driver;
    }

    fn is_dead(&self) -> bool {
        false
    }

    fn can_match(&self) -> bool {
        self.inner().device_common.can_match
    }

    fn set_can_match(&self, can_match: bool) {
        self.inner().device_common.can_match = can_match;
    }
    fn state_synced(&self) -> bool {
        true
    }

    fn dev_parent(&self) -> Option<Weak<dyn Device>> {
        self.inner().device_common.get_parent_weak_or_clear()
    }

    fn set_dev_parent(&self, parent: Option<Weak<dyn Device>>) {
        self.inner().device_common.parent = parent;
    }

    fn attribute_groups(&self) -> Option<&'static [&'static dyn AttributeGroup]> {
        None
    }
}

impl VirtIODevice for VirtIONetDevice {
    fn handle_irq(&self, _irq: IrqNumber) -> Result<IrqReturn, SystemError> {
        let Some(iface) = self.iface() else {
            error!(
                "VirtIONetDevice '{:?}' has no associated iface to handle irq",
                self.dev_id.id()
            );
            return Ok(IrqReturn::NotHandled);
        };

        let Some(napi) = iface.napi_struct() else {
            log::error!("Virtio net device {} has no napi_struct", iface.name());
            return Ok(IrqReturn::NotHandled);
        };

        napi_schedule(napi);

        // self.netns.wakeup_poll_thread();
        return Ok(IrqReturn::Handled);
    }

    fn dev_id(&self) -> &Arc<DeviceId> {
        return &self.dev_id;
    }

    fn set_device_name(&self, name: String) {
        self.inner().name = Some(name);
    }

    fn device_name(&self) -> String {
        self.inner()
            .name
            .clone()
            .unwrap_or_else(|| "virtio_net".to_string())
    }

    fn set_virtio_device_index(&self, index: VirtIODeviceIndex) {
        self.inner().virtio_index = Some(index);
    }

    fn virtio_device_index(&self) -> Option<VirtIODeviceIndex> {
        return self.inner().virtio_index;
    }

    fn device_type_id(&self) -> u32 {
        virtio_drivers::transport::DeviceType::Network as u32
    }

    fn vendor(&self) -> u32 {
        VIRTIO_VENDOR_ID.into()
    }

    fn irq(&self) -> Option<IrqNumber> {
        None
    }
}

pub struct VirtIoNetImpl {
    inner: VirtIONet<HalImpl, VirtIOTransport, 2>,
}

impl VirtIoNetImpl {
    const fn new(inner: VirtIONet<HalImpl, VirtIOTransport, 2>) -> Self {
        Self { inner }
    }
}

impl Deref for VirtIoNetImpl {
    type Target = VirtIONet<HalImpl, VirtIOTransport, 2>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for VirtIoNetImpl {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

unsafe impl Send for VirtIoNetImpl {}
unsafe impl Sync for VirtIoNetImpl {}

#[derive(Debug)]
struct VirtIONicDeviceInnerWrapper(UnsafeCell<VirtIONicDeviceInner>);
unsafe impl Send for VirtIONicDeviceInnerWrapper {}
unsafe impl Sync for VirtIONicDeviceInnerWrapper {}

impl Deref for VirtIONicDeviceInnerWrapper {
    type Target = VirtIONicDeviceInner;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0.get() }
    }
}
impl DerefMut for VirtIONicDeviceInnerWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.0.get() }
    }
}

#[allow(clippy::mut_from_ref)]
impl VirtIONicDeviceInnerWrapper {
    fn force_get_mut(&self) -> &mut <VirtIONicDeviceInnerWrapper as Deref>::Target {
        unsafe { &mut *self.0.get() }
    }
}

/// Virtio网络设备驱动(加锁)
pub struct VirtIONicDeviceInner {
    pub inner: Arc<SpinLock<VirtIoNetImpl>>,
}

impl Clone for VirtIONicDeviceInner {
    fn clone(&self) -> Self {
        return VirtIONicDeviceInner {
            inner: self.inner.clone(),
        };
    }
}

impl Debug for VirtIONicDeviceInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIONicDriver").finish()
    }
}

#[cast_to([sync] Iface)]
#[cast_to([sync] Device)]
#[derive(Debug)]
pub struct VirtioInterface {
    device_inner: VirtIONicDeviceInnerWrapper,
    iface_name: String,
    iface_common: super::IfaceCommon,
    inner: SpinLock<InnerVirtIOInterface>,
    locked_kobj_state: LockedKObjectState,
}

// // 先手糊为virtio实现这些，后面系统要是有了其他类型网卡，这些实现就得实现成一个单独的trait
// impl VirtioInterface {
//     /// 消耗token然后主动发送一个 arp 数据包
//     pub fn emit_arp(arp_repr: &ArpRepr, tx_token: VirtioNetToken) {
//         let ether_repr = match arp_repr {
//             ArpRepr::EthernetIpv4 {
//                 source_hardware_addr,
//                 target_hardware_addr,
//                 ..
//             } => EthernetRepr {
//                 src_addr: *source_hardware_addr,
//                 dst_addr: *target_hardware_addr,
//                 ethertype: EthernetProtocol::Arp,
//             },
//             _ => return,
//         };

//         tx_token.consume(ether_repr.buffer_len() + arp_repr.buffer_len(), |buffer| {
//             let mut frame = EthernetFrame::new_unchecked(buffer);
//             ether_repr.emit(&mut frame);

//             let mut pkt = ArpPacket::new_unchecked(frame.payload_mut());
//             arp_repr.emit(&mut pkt);
//         });
//     }

//     /// 解析 arp 包并处理
//     pub fn process_arp(&self, arp_repr: &ArpRepr) -> Option<ArpRepr> {
//         match arp_repr {
//             ArpRepr::EthernetIpv4 {
//                 operation: ArpOperation::Reply,
//                 source_hardware_addr,
//                 source_protocol_addr,
//                 ..
//             } => {
//                 if !source_hardware_addr.is_unicast()
//                     || !self
//                         .common()
//                         .smol_iface
//                         .lock()
//                         .context()
//                         .in_same_network(&IpAddress::Ipv4(*source_protocol_addr))
//                 {
//                     return None;
//                 }

//                 self.common().router_common_data.arp_table.write().insert(
//                     IpAddress::Ipv4(*source_protocol_addr),
//                     *source_hardware_addr,
//                 );

//                 None
//             }
//             ArpRepr::EthernetIpv4 {
//                 operation: ArpOperation::Request,
//                 source_hardware_addr,
//                 source_protocol_addr,
//                 target_protocol_addr,
//                 ..
//             } => {
//                 if !source_hardware_addr.is_unicast() || !source_protocol_addr.x_is_unicast() {
//                     return None;
//                 }

//                 if self
//                     .common()
//                     .smol_iface
//                     .lock()
//                     .context()
//                     .ipv4_addr()
//                     .is_none_or(|addr| addr != *target_protocol_addr)
//                 {
//                     return None;
//                 }
//                 Some(ArpRepr::EthernetIpv4 {
//                     operation: ArpOperation::Reply,
//                     source_hardware_addr: self.mac(),
//                     source_protocol_addr: *target_protocol_addr,
//                     target_hardware_addr: *source_hardware_addr,
//                     target_protocol_addr: *source_protocol_addr,
//                 })
//             }
//             _ => None,
//         }
//     }
// }

#[derive(Debug)]
struct InnerVirtIOInterface {
    kobj_common: KObjectCommonData,
    device_common: DeviceCommonData,
    netdevice_common: NetDeviceCommonData,
}

impl VirtioInterface {
    pub fn new(mut device_inner: VirtIONicDeviceInner) -> Arc<Self> {
        let iface_id = generate_iface_id();
        let mut iface_config = iface::Config::new(wire::HardwareAddress::Ethernet(
            wire::EthernetAddress(device_inner.inner.lock().mac_address()),
        ));
        iface_config.random_seed = rand() as u64;

        let iface = iface::Interface::new(iface_config, &mut device_inner, Instant::now().into());

        let flags = InterfaceFlags::UP
            | InterfaceFlags::BROADCAST
            | InterfaceFlags::RUNNING
            | InterfaceFlags::MULTICAST
            | InterfaceFlags::LOWER_UP;

        let iface = Arc::new(VirtioInterface {
            device_inner: VirtIONicDeviceInnerWrapper(UnsafeCell::new(device_inner)),
            locked_kobj_state: LockedKObjectState::default(),
            iface_name: format!("eth{}", iface_id),
            iface_common: super::IfaceCommon::new(
                iface_id,
                crate::driver::net::types::InterfaceType::EETHER,
                flags,
                iface,
            ),
            inner: SpinLock::new(InnerVirtIOInterface {
                kobj_common: KObjectCommonData::default(),
                device_common: DeviceCommonData::default(),
                netdevice_common: NetDeviceCommonData::default(),
            }),
        });

        // 设置napi struct
        let napi_struct = NapiStruct::new(iface.clone(), 10);
        *iface.common().napi_struct.write() = Some(napi_struct);

        iface
    }

    fn inner(&self) -> SpinLockGuard<'_, InnerVirtIOInterface> {
        return self.inner.lock();
    }

    /// 获取网卡接口的名称
    #[allow(dead_code)]
    pub fn iface_name(&self) -> String {
        self.iface_name.clone()
    }
}

impl Drop for VirtioInterface {
    fn drop(&mut self) {
        // 从全局的网卡接口信息表中删除这个网卡的接口信息
        // NET_DEVICES.write_irqsave().remove(&self.nic_id());
        if let Some(ns) = self.net_namespace() {
            ns.remove_device(&self.nic_id());
        }
    }
}

impl Device for VirtioInterface {
    fn dev_type(&self) -> DeviceType {
        DeviceType::Net
    }

    fn id_table(&self) -> IdTable {
        IdTable::new(VIRTIO_NET_BASENAME.to_string(), None)
    }

    fn bus(&self) -> Option<Weak<dyn Bus>> {
        self.inner().device_common.bus.clone()
    }

    fn set_bus(&self, bus: Option<Weak<dyn Bus>>) {
        self.inner().device_common.bus = bus;
    }

    fn class(&self) -> Option<Arc<dyn Class>> {
        let mut guard = self.inner();
        let r = guard.device_common.class.clone()?.upgrade();
        if r.is_none() {
            guard.device_common.class = None;
        }

        return r;
    }

    fn set_class(&self, class: Option<Weak<dyn Class>>) {
        self.inner().device_common.class = class;
    }

    fn driver(&self) -> Option<Arc<dyn Driver>> {
        let r = self.inner().device_common.driver.clone()?.upgrade();
        if r.is_none() {
            self.inner().device_common.driver = None;
        }

        return r;
    }

    fn set_driver(&self, driver: Option<Weak<dyn Driver>>) {
        self.inner().device_common.driver = driver;
    }

    fn is_dead(&self) -> bool {
        false
    }

    fn can_match(&self) -> bool {
        self.inner().device_common.can_match
    }

    fn set_can_match(&self, can_match: bool) {
        self.inner().device_common.can_match = can_match;
    }

    fn state_synced(&self) -> bool {
        true
    }

    fn dev_parent(&self) -> Option<Weak<dyn Device>> {
        self.inner().device_common.get_parent_weak_or_clear()
    }

    fn set_dev_parent(&self, parent: Option<Weak<dyn Device>>) {
        self.inner().device_common.parent = parent;
    }
}

impl VirtIONicDeviceInner {
    pub fn new(driver_net: VirtIONet<HalImpl, VirtIOTransport, 2>) -> Self {
        let mut iface_config = iface::Config::new(wire::HardwareAddress::Ethernet(
            wire::EthernetAddress(driver_net.mac_address()),
        ));

        iface_config.random_seed = rand() as u64;

        let inner = Arc::new(SpinLock::new(VirtIoNetImpl::new(driver_net)));
        let result = VirtIONicDeviceInner { inner };
        return result;
    }
}

pub struct VirtioNetToken {
    driver: VirtIONicDeviceInner,
    rx_buffer: Option<virtio_drivers::device::net::RxBuffer>,
}

impl VirtioNetToken {
    pub fn new(
        driver: VirtIONicDeviceInner,
        rx_buffer: Option<virtio_drivers::device::net::RxBuffer>,
    ) -> Self {
        return Self { driver, rx_buffer };
    }
}

impl phy::Device for VirtIONicDeviceInner {
    type RxToken<'a>
        = VirtioNetToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtioNetToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.inner.lock().receive() {
            Ok(buf) => Some((
                VirtioNetToken::new(self.clone(), Some(buf)),
                VirtioNetToken::new(self.clone(), None),
            )),
            Err(virtio_drivers::Error::NotReady) => None,
            Err(err) => panic!("VirtIO receive failed: {}", err),
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        // debug!("VirtioNet: transmit");
        if self.inner.lock_irqsave().can_send() {
            // debug!("VirtioNet: can send");
            return Some(VirtioNetToken::new(self.clone(), None));
        } else {
            // debug!("VirtioNet: can not send");
            return None;
        }
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        // 网卡的最大传输单元. 请与IP层的MTU进行区分。这个值应当是网卡的最大传输单元，而不是IP层的MTU。
        caps.max_transmission_unit = 2000;
        /*
           Maximum burst size, in terms of MTU.
           The network device is unable to send or receive bursts large than the value returned by this function.
           If None, there is no fixed limit on burst size, e.g. if network buffers are dynamically allocated.
        */
        caps.max_burst_size = Some(1);
        return caps;
    }
}

impl phy::TxToken for VirtioNetToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // // 为了线程安全，这里需要对VirtioNet进行加【写锁】，以保证对设备的互斥访问。
        let mut driver_net = self.driver.inner.lock();
        let mut tx_buf = driver_net.new_tx_buffer(len);
        let result = f(tx_buf.packet_mut());
        driver_net.send(tx_buf).expect("virtio_net send failed");
        return result;
    }
}

impl phy::RxToken for VirtioNetToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        // 为了线程安全，这里需要对VirtioNet进行加【写锁】，以保证对设备的互斥访问。
        let rx_buf = self.rx_buffer.unwrap();
        let result = f(rx_buf.packet());
        self.driver
            .inner
            .lock()
            .recycle_rx_buffer(rx_buf)
            .expect("virtio_net recv failed");
        result
    }
}

/// @brief virtio-net 驱动的初始化与测试
pub fn virtio_net(
    transport: VirtIOTransport,
    dev_id: Arc<DeviceId>,
    dev_parent: Option<Arc<dyn Device>>,
) {
    let virtio_net_deivce = VirtIONetDevice::new(transport, dev_id);
    if let Some(virtio_net_deivce) = virtio_net_deivce {
        debug!("VirtIONetDevice '{:?}' created", virtio_net_deivce.dev_id);
        if let Some(dev_parent) = dev_parent {
            virtio_net_deivce.set_dev_parent(Some(Arc::downgrade(&dev_parent)));
        }
        virtio_device_manager()
            .device_add(virtio_net_deivce.clone() as Arc<dyn VirtIODevice>)
            .expect("Add virtio net failed");
    }
}

impl Iface for VirtioInterface {
    fn common(&self) -> &super::IfaceCommon {
        &self.iface_common
    }

    fn mac(&self) -> wire::EthernetAddress {
        let mac: [u8; 6] = self.device_inner.inner.lock().mac_address();
        return wire::EthernetAddress::from_bytes(&mac);
    }

    #[inline]
    fn iface_name(&self) -> String {
        return self.iface_name.clone();
    }

    fn poll(&self) -> bool {
        // log::debug!("VirtioInterface: poll");
        self.iface_common.poll(self.device_inner.force_get_mut())
    }

    // fn as_any_ref(&'static self) -> &'static dyn core::any::Any {
    //     return self;
    // }

    fn addr_assign_type(&self) -> u8 {
        return self.inner().netdevice_common.addr_assign_type;
    }

    fn net_device_type(&self) -> u16 {
        self.inner().netdevice_common.net_device_type = 1; // 以太网设备
        return self.inner().netdevice_common.net_device_type;
    }

    fn net_state(&self) -> NetDeivceState {
        return self.inner().netdevice_common.state;
    }

    fn set_net_state(&self, state: NetDeivceState) {
        self.inner().netdevice_common.state |= state;
    }

    fn operstate(&self) -> Operstate {
        return self.inner().netdevice_common.operstate;
    }

    fn set_operstate(&self, state: Operstate) {
        self.inner().netdevice_common.operstate = state;
    }

    fn mtu(&self) -> usize {
        use smoltcp::phy::Device;
        self.device_inner
            .force_get_mut()
            .capabilities()
            .max_transmission_unit
    }
}

impl KObject for VirtioInterface {
    fn as_any_ref(&self) -> &dyn core::any::Any {
        self
    }

    fn set_inode(&self, inode: Option<Arc<KernFSInode>>) {
        self.inner().kobj_common.kern_inode = inode;
    }

    fn inode(&self) -> Option<Arc<KernFSInode>> {
        self.inner().kobj_common.kern_inode.clone()
    }

    fn parent(&self) -> Option<Weak<dyn KObject>> {
        self.inner().kobj_common.parent.clone()
    }

    fn set_parent(&self, parent: Option<Weak<dyn KObject>>) {
        self.inner().kobj_common.parent = parent;
    }

    fn kset(&self) -> Option<Arc<KSet>> {
        self.inner().kobj_common.kset.clone()
    }

    fn set_kset(&self, kset: Option<Arc<KSet>>) {
        self.inner().kobj_common.kset = kset;
    }

    fn kobj_type(&self) -> Option<&'static dyn KObjType> {
        self.inner().kobj_common.kobj_type
    }

    fn name(&self) -> String {
        self.iface_name.clone()
    }

    fn set_name(&self, _name: String) {
        // do nothing
    }

    fn kobj_state(&self) -> RwLockReadGuard<'_, KObjectState> {
        self.locked_kobj_state.read()
    }

    fn kobj_state_mut(&self) -> RwLockWriteGuard<'_, KObjectState> {
        self.locked_kobj_state.write()
    }

    fn set_kobj_state(&self, state: KObjectState) {
        *self.locked_kobj_state.write() = state;
    }

    fn set_kobj_type(&self, ktype: Option<&'static dyn KObjType>) {
        self.inner().kobj_common.kobj_type = ktype;
    }
}

#[unified_init(INITCALL_POSTCORE)]
fn virtio_net_driver_init() -> Result<(), SystemError> {
    let driver = VirtIONetDriver::new();
    virtio_driver_manager().register(driver.clone() as Arc<dyn VirtIODriver>)?;
    unsafe {
        VIRTIO_NET_DRIVER = Some(driver);
    }

    return Ok(());
}

#[derive(Debug)]
#[cast_to([sync] VirtIODriver)]
#[cast_to([sync] Driver)]
struct VirtIONetDriver {
    inner: SpinLock<InnerVirtIODriver>,
    kobj_state: LockedKObjectState,
}

impl VirtIONetDriver {
    pub fn new() -> Arc<Self> {
        let inner = InnerVirtIODriver {
            virtio_driver_common: VirtIODriverCommonData::default(),
            driver_common: DriverCommonData::default(),
            kobj_common: KObjectCommonData::default(),
        };

        let id_table = VirtioDeviceId::new(
            virtio_drivers::transport::DeviceType::Network as u32,
            VIRTIO_VENDOR_ID.into(),
        );
        let result = VirtIONetDriver {
            inner: SpinLock::new(inner),
            kobj_state: LockedKObjectState::default(),
        };
        result.add_virtio_id(id_table);

        return Arc::new(result);
    }

    fn inner(&self) -> SpinLockGuard<'_, InnerVirtIODriver> {
        return self.inner.lock();
    }
}

#[derive(Debug)]
struct InnerVirtIODriver {
    virtio_driver_common: VirtIODriverCommonData,
    driver_common: DriverCommonData,
    kobj_common: KObjectCommonData,
}

impl VirtIODriver for VirtIONetDriver {
    fn probe(&self, device: &Arc<dyn VirtIODevice>) -> Result<(), SystemError> {
        log::debug!("VirtIONetDriver::probe()");
        let virtio_net_device = device
            .clone()
            .arc_any()
            .downcast::<VirtIONetDevice>()
            .map_err(|_| {
                error!(
                    "VirtIONetDriver::probe() failed: device is not a VirtIODevice. Device: '{:?}'",
                    device.name()
                );
                SystemError::EINVAL
            })?;

        let iface: Arc<VirtioInterface> =
            VirtioInterface::new(virtio_net_device.inner().device_inner.clone());
        // 标识网络设备已经启动
        iface.set_net_state(NetDeivceState::__LINK_STATE_START);
        // 设置iface的父设备为virtio_net_device
        iface.set_dev_parent(Some(Arc::downgrade(&virtio_net_device) as Weak<dyn Device>));
        // 在sysfs中注册iface
        register_netdevice(iface.clone() as Arc<dyn Iface>)?;

        // 将virtio_net_device和iface关联起来
        virtio_net_device.set_iface(&iface);

        // 将网卡的接口信息注册到全局的网卡接口信息表中
        // NET_DEVICES
        //     .write_irqsave()
        //     .insert(iface.nic_id(), iface.clone());
        INIT_NET_NAMESPACE.add_device(iface.clone());
        iface
            .iface_common
            .set_net_namespace(INIT_NET_NAMESPACE.clone());
        INIT_NET_NAMESPACE.set_default_iface(iface.clone());

        virtio_irq_manager()
            .register_device(device.clone())
            .expect("Register virtio net irq failed");

        return Ok(());
    }

    fn virtio_id_table(&self) -> Vec<VirtioDeviceId> {
        self.inner().virtio_driver_common.id_table.clone()
    }

    fn add_virtio_id(&self, id: VirtioDeviceId) {
        self.inner().virtio_driver_common.id_table.push(id);
    }
}

impl Driver for VirtIONetDriver {
    fn id_table(&self) -> Option<IdTable> {
        Some(IdTable::new(VIRTIO_NET_BASENAME.to_string(), None))
    }

    fn add_device(&self, device: Arc<dyn Device>) {
        let virtio_net_device = device
            .arc_any()
            .downcast::<VirtIONetDevice>()
            .expect("VirtIONetDriver::add_device() failed: device is not a VirtioInterface");

        self.inner()
            .driver_common
            .devices
            .push(virtio_net_device as Arc<dyn Device>);
    }

    fn delete_device(&self, device: &Arc<dyn Device>) {
        let _virtio_net_device = device
            .clone()
            .arc_any()
            .downcast::<VirtIONetDevice>()
            .expect("VirtIONetDriver::delete_device() failed: device is not a VirtioInterface");

        let mut guard = self.inner();
        let index = guard
            .driver_common
            .devices
            .iter()
            .position(|dev| Arc::ptr_eq(device, dev))
            .expect("VirtIONetDriver::delete_device() failed: device not found");

        guard.driver_common.devices.remove(index);
    }

    fn devices(&self) -> Vec<Arc<dyn Device>> {
        self.inner().driver_common.devices.clone()
    }

    fn bus(&self) -> Option<Weak<dyn Bus>> {
        Some(Arc::downgrade(&virtio_bus()) as Weak<dyn Bus>)
    }

    fn set_bus(&self, _bus: Option<Weak<dyn Bus>>) {
        // do nothing
    }
}

impl KObject for VirtIONetDriver {
    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn set_inode(&self, inode: Option<Arc<KernFSInode>>) {
        self.inner().kobj_common.kern_inode = inode;
    }

    fn inode(&self) -> Option<Arc<KernFSInode>> {
        self.inner().kobj_common.kern_inode.clone()
    }

    fn parent(&self) -> Option<Weak<dyn KObject>> {
        self.inner().kobj_common.parent.clone()
    }

    fn set_parent(&self, parent: Option<Weak<dyn KObject>>) {
        self.inner().kobj_common.parent = parent;
    }

    fn kset(&self) -> Option<Arc<KSet>> {
        self.inner().kobj_common.kset.clone()
    }

    fn set_kset(&self, kset: Option<Arc<KSet>>) {
        self.inner().kobj_common.kset = kset;
    }

    fn kobj_type(&self) -> Option<&'static dyn KObjType> {
        self.inner().kobj_common.kobj_type
    }

    fn set_kobj_type(&self, ktype: Option<&'static dyn KObjType>) {
        self.inner().kobj_common.kobj_type = ktype;
    }

    fn name(&self) -> String {
        VIRTIO_NET_BASENAME.to_string()
    }

    fn set_name(&self, _name: String) {
        // do nothing
    }

    fn kobj_state(&self) -> RwLockReadGuard<'_, KObjectState> {
        self.kobj_state.read()
    }

    fn kobj_state_mut(&self) -> RwLockWriteGuard<'_, KObjectState> {
        self.kobj_state.write()
    }

    fn set_kobj_state(&self, state: KObjectState) {
        *self.kobj_state.write() = state;
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #3：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\driver\virtio\transport_pci.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
//! PCI transport for VirtIO.

use crate::driver::base::device::DeviceId;
use crate::driver::pci::pci::{
    BusDeviceFunction, PciDeviceStructure, PciDeviceStructureGeneralDevice, PciError,
    PciStandardDeviceBar, PCI_CAP_ID_VNDR,
};

use crate::driver::pci::root::pci_root_0;

use crate::exception::IrqNumber;

use crate::libs::volatile::{
    volread, volwrite, ReadOnly, Volatile, VolatileReadable, VolatileWritable, WriteOnly,
};
use crate::mm::VirtAddr;

use alloc::sync::Arc;
use core::{
    fmt::{self, Display, Formatter},
    mem::{align_of, size_of},
    ptr::{self, addr_of_mut, NonNull},
};
use virtio_drivers::{
    transport::{DeviceStatus, DeviceType, Transport},
    Error, Hal, PhysAddr,
};

use super::VIRTIO_VENDOR_ID;

/// The offset to add to a VirtIO device ID to get the corresponding PCI device ID.
/// PCI Virtio设备的DEVICE_ID 的offset
const PCI_DEVICE_ID_OFFSET: u16 = 0x1040;
/// PCI Virtio 设备的DEVICE_ID及其对应的设备类型
const TRANSITIONAL_NETWORK: u16 = 0x1000;
const TRANSITIONAL_BLOCK: u16 = 0x1001;
const TRANSITIONAL_MEMORY_BALLOONING: u16 = 0x1002;
const TRANSITIONAL_CONSOLE: u16 = 0x1003;
const TRANSITIONAL_SCSI_HOST: u16 = 0x1004;
const TRANSITIONAL_ENTROPY_SOURCE: u16 = 0x1005;
const TRANSITIONAL_9P_TRANSPORT: u16 = 0x1009;

/// The offset of the bar field within `virtio_pci_cap`.
const CAP_BAR_OFFSET: u8 = 4;
/// The offset of the offset field with `virtio_pci_cap`.
const CAP_BAR_OFFSET_OFFSET: u8 = 8;
/// The offset of the `length` field within `virtio_pci_cap`.
const CAP_LENGTH_OFFSET: u8 = 12;
/// The offset of the`notify_off_multiplier` field within `virtio_pci_notify_cap`.
const CAP_NOTIFY_OFF_MULTIPLIER_OFFSET: u8 = 16;

/// Common configuration.
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notifications.
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR Status.
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device specific configuration.
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Virtio设备接收中断的设备号
const VIRTIO_RECV_VECTOR: IrqNumber = IrqNumber::new(56);
/// Virtio设备接收中断的设备号的表项号
const VIRTIO_RECV_VECTOR_INDEX: u16 = 0;
// 接收的queue号
const QUEUE_RECEIVE: u16 = 0;
///@brief device id 转换为设备类型
///@param pci_device_id，device_id
///@return DeviceType 对应的设备类型
fn device_type(pci_device_id: u16) -> DeviceType {
    match pci_device_id {
        TRANSITIONAL_NETWORK => DeviceType::Network,
        TRANSITIONAL_BLOCK => DeviceType::Block,
        TRANSITIONAL_MEMORY_BALLOONING => DeviceType::MemoryBalloon,
        TRANSITIONAL_CONSOLE => DeviceType::Console,
        TRANSITIONAL_SCSI_HOST => DeviceType::ScsiHost,
        TRANSITIONAL_ENTROPY_SOURCE => DeviceType::EntropySource,
        TRANSITIONAL_9P_TRANSPORT => DeviceType::_9P,
        id if id >= PCI_DEVICE_ID_OFFSET => DeviceType::from(id - PCI_DEVICE_ID_OFFSET),
        _ => DeviceType::Invalid,
    }
}

/// PCI transport for VirtIO.
///
/// Ref: 4.1 Virtio Over PCI Bus
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PciTransport {
    device_type: DeviceType,
    /// The bus, device and function identifier for the VirtIO device.
    _bus_device_function: BusDeviceFunction,
    /// The common configuration structure within some BAR.
    common_cfg: NonNull<CommonCfg>,
    /// The start of the queue notification region within some BAR.
    notify_region: NonNull<[WriteOnly<u16>]>,
    notify_off_multiplier: u32,
    /// The ISR status register within some BAR.
    isr_status: NonNull<Volatile<u8>>,
    /// The VirtIO device-specific configuration within some BAR.
    config_space: Option<NonNull<[u32]>>,
    irq: IrqNumber,
    dev_id: Arc<DeviceId>,
    device: Arc<PciDeviceStructureGeneralDevice>,
}

impl PciTransport {
    /// Construct a new PCI VirtIO device driver for the given device function on the given PCI
    /// root controller.
    ///
    /// ## 参数
    ///
    /// - `device` - The PCI device structure for the VirtIO device.
    /// - `irq_handler` - An optional handler for the device's interrupt. If `None`, a default
    ///   handler `DefaultVirtioIrqHandler` will be used.
    /// - `irq_number_offset` - Currently, this parameter is just simple make a offset to the irq number, cause it's not be allowed to have the same irq number within different device
    #[allow(clippy::extra_unused_type_parameters)]
    pub fn new<H: Hal>(
        device: Arc<PciDeviceStructureGeneralDevice>,
        dev_id: Arc<DeviceId>,
    ) -> Result<Self, VirtioPciError> {
        let irq = VIRTIO_RECV_VECTOR;
        let header = &device.common_header;
        let bus_device_function = header.bus_device_function;
        if header.vendor_id != VIRTIO_VENDOR_ID {
            return Err(VirtioPciError::InvalidVendorId(header.vendor_id));
        }
        let device_type = device_type(header.device_id);
        // Find the PCI capabilities we need.
        let mut common_cfg: Option<VirtioCapabilityInfo> = None;
        let mut notify_cfg: Option<VirtioCapabilityInfo> = None;
        let mut notify_off_multiplier = 0;
        let mut isr_cfg = None;
        let mut device_cfg = None;
        device.bar_ioremap().unwrap()?;
        device.enable_master();
        let standard_device = device.as_standard_device().unwrap();
        // 目前缺少对PCI设备中断号的统一管理，所以这里需要指定一个中断号。不能与其他中断重复
        let irq_vector = standard_device.irq_vector_mut().unwrap();
        irq_vector.write().push(irq);

        // panic!();
        //device_capability为迭代器，遍历其相当于遍历所有的cap空间
        for capability in device.capabilities().unwrap() {
            if capability.id != PCI_CAP_ID_VNDR {
                continue;
            }
            let cap_len = capability.private_header as u8;
            let cfg_type = (capability.private_header >> 8) as u8;
            if cap_len < 16 {
                continue;
            }
            let struct_info = VirtioCapabilityInfo {
                bar: pci_root_0().read_config(
                    bus_device_function,
                    (capability.offset + CAP_BAR_OFFSET).into(),
                ) as u8,
                offset: pci_root_0().read_config(
                    bus_device_function,
                    (capability.offset + CAP_BAR_OFFSET_OFFSET).into(),
                ),
                length: pci_root_0().read_config(
                    bus_device_function,
                    (capability.offset + CAP_LENGTH_OFFSET).into(),
                ),
            };

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG if common_cfg.is_none() => {
                    common_cfg = Some(struct_info);
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG if cap_len >= 20 && notify_cfg.is_none() => {
                    notify_cfg = Some(struct_info);
                    notify_off_multiplier = pci_root_0().read_config(
                        bus_device_function,
                        (capability.offset + CAP_NOTIFY_OFF_MULTIPLIER_OFFSET).into(),
                    );
                }
                VIRTIO_PCI_CAP_ISR_CFG if isr_cfg.is_none() => {
                    isr_cfg = Some(struct_info);
                }
                VIRTIO_PCI_CAP_DEVICE_CFG if device_cfg.is_none() => {
                    device_cfg = Some(struct_info);
                }
                _ => {}
            }
        }

        let common_cfg = get_bar_region::<_>(
            &device.standard_device_bar.read(),
            &common_cfg.ok_or(VirtioPciError::MissingCommonConfig)?,
        )?;

        let notify_cfg = notify_cfg.ok_or(VirtioPciError::MissingNotifyConfig)?;
        if notify_off_multiplier % 2 != 0 {
            return Err(VirtioPciError::InvalidNotifyOffMultiplier(
                notify_off_multiplier,
            ));
        }
        //debug!("notify.offset={},notify.length={}",notify_cfg.offset,notify_cfg.length);
        let notify_region =
            get_bar_region_slice::<_>(&device.standard_device_bar.read(), &notify_cfg)?;
        let isr_status = get_bar_region::<_>(
            &device.standard_device_bar.read(),
            &isr_cfg.ok_or(VirtioPciError::MissingIsrConfig)?,
        )?;
        let config_space = if let Some(device_cfg) = device_cfg {
            Some(get_bar_region_slice::<_>(
                &device.standard_device_bar.read(),
                &device_cfg,
            )?)
        } else {
            None
        };
        Ok(Self {
            device_type,
            _bus_device_function: bus_device_function,
            common_cfg,
            notify_region,
            notify_off_multiplier,
            isr_status,
            config_space,
            irq,
            dev_id,
            device,
        })
    }

    pub fn pci_device(&self) -> Arc<PciDeviceStructureGeneralDevice> {
        self.device.clone()
    }

    pub fn irq(&self) -> IrqNumber {
        self.irq
    }
}

impl Transport for PciTransport {
    fn device_type(&self) -> DeviceType {
        self.device_type
    }

    fn read_device_features(&mut self) -> u64 {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, device_feature_select, 0);
            let mut device_features_bits = volread!(self.common_cfg, device_feature) as u64;
            volwrite!(self.common_cfg, device_feature_select, 1);
            device_features_bits |= (volread!(self.common_cfg, device_feature) as u64) << 32;
            device_features_bits
        }
    }

    fn write_driver_features(&mut self, driver_features: u64) {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, driver_feature_select, 0);
            volwrite!(self.common_cfg, driver_feature, driver_features as u32);
            volwrite!(self.common_cfg, driver_feature_select, 1);
            volwrite!(
                self.common_cfg,
                driver_feature,
                (driver_features >> 32) as u32
            );
        }
    }

    fn max_queue_size(&mut self, queue: u16) -> u32 {
        unsafe {
            volwrite!(self.common_cfg, queue_select, queue);
            volread!(self.common_cfg, queue_size).into()
        }
    }

    fn notify(&mut self, queue: u16) {
        // Safe because the common config and notify region pointers are valid and we checked in
        // get_bar_region that they were aligned.
        unsafe {
            volwrite!(self.common_cfg, queue_select, queue);
            // TODO: Consider caching this somewhere (per queue).
            let queue_notify_off = volread!(self.common_cfg, queue_notify_off);

            let offset_bytes = usize::from(queue_notify_off) * self.notify_off_multiplier as usize;
            let index = offset_bytes / size_of::<u16>();
            addr_of_mut!((*self.notify_region.as_ptr())[index]).vwrite(queue);
        }
    }

    fn set_status(&mut self, status: DeviceStatus) {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, device_status, status.bits() as u8);
        }
    }

    fn get_status(&self) -> DeviceStatus {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe { DeviceStatus::from_bits_truncate(volread!(self.common_cfg, device_status).into()) }
    }

    fn set_guest_page_size(&mut self, _guest_page_size: u32) {
        // No-op, the PCI transport doesn't care.
    }
    fn requires_legacy_layout(&self) -> bool {
        false
    }
    fn queue_set(
        &mut self,
        queue: u16,
        size: u32,
        descriptors: PhysAddr,
        driver_area: PhysAddr,
        device_area: PhysAddr,
    ) {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, queue_select, queue);
            volwrite!(self.common_cfg, queue_size, size as u16);
            volwrite!(self.common_cfg, queue_desc, descriptors as u64);
            volwrite!(self.common_cfg, queue_driver, driver_area as u64);
            volwrite!(self.common_cfg, queue_device, device_area as u64);
            // 这里设置队列中断对应的中断项
            if queue == QUEUE_RECEIVE {
                volwrite!(self.common_cfg, queue_msix_vector, VIRTIO_RECV_VECTOR_INDEX);
                let vector = volread!(self.common_cfg, queue_msix_vector);
                if vector != VIRTIO_RECV_VECTOR_INDEX {
                    panic!("Vector set failed");
                }
            }
            volwrite!(self.common_cfg, queue_enable, 1);
        }
    }

    fn queue_unset(&mut self, queue: u16) {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, queue_select, queue);
            volwrite!(self.common_cfg, queue_size, 0);
            volwrite!(self.common_cfg, queue_desc, 0);
            volwrite!(self.common_cfg, queue_driver, 0);
            volwrite!(self.common_cfg, queue_device, 0);
        }
    }

    fn queue_used(&mut self, queue: u16) -> bool {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        unsafe {
            volwrite!(self.common_cfg, queue_select, queue);
            volread!(self.common_cfg, queue_enable) == 1
        }
    }

    fn ack_interrupt(&mut self) -> bool {
        // Safe because the common config pointer is valid and we checked in get_bar_region that it
        // was aligned.
        // Reading the ISR status resets it to 0 and causes the device to de-assert the interrupt.
        let isr_status = unsafe { self.isr_status.as_ptr().vread() };
        // TODO: Distinguish between queue interrupt and device configuration interrupt.
        isr_status & 0x3 != 0
    }

    fn config_space<T>(&self) -> Result<NonNull<T>, Error> {
        if let Some(config_space) = self.config_space {
            if size_of::<T>() > config_space.len() * size_of::<u32>() {
                Err(Error::ConfigSpaceTooSmall)
            } else if align_of::<T>() > 4 {
                // Panic as this should only happen if the driver is written incorrectly.
                panic!(
                    "Driver expected config space alignment of {} bytes, but VirtIO only guarantees 4 byte alignment.",
                    align_of::<T>()
                );
            } else {
                // TODO: Use NonNull::as_non_null_ptr once it is stable.
                let config_space_ptr = NonNull::new(config_space.as_ptr() as *mut u32).unwrap();
                Ok(config_space_ptr.cast())
            }
        } else {
            Err(Error::ConfigSpaceMissing)
        }
    }
}

impl Drop for PciTransport {
    fn drop(&mut self) {
        // Reset the device when the transport is dropped.
        self.set_status(DeviceStatus::empty());

        // todo: 调用pci的中断释放函数，并且在virtio_irq_manager里面删除对应的设备的中断
    }
}

#[repr(C)]
struct CommonCfg {
    device_feature_select: Volatile<u32>,
    device_feature: ReadOnly<u32>,
    driver_feature_select: Volatile<u32>,
    driver_feature: Volatile<u32>,
    msix_config: Volatile<u16>,
    num_queues: ReadOnly<u16>,
    device_status: Volatile<u8>,
    config_generation: ReadOnly<u8>,
    queue_select: Volatile<u16>,
    queue_size: Volatile<u16>,
    queue_msix_vector: Volatile<u16>,
    queue_enable: Volatile<u16>,
    queue_notify_off: Volatile<u16>,
    queue_desc: Volatile<u64>,
    queue_driver: Volatile<u64>,
    queue_device: Volatile<u64>,
}

/// Information about a VirtIO structure within some BAR, as provided by a `virtio_pci_cap`.
/// cfg空间在哪个bar的多少偏移处，长度多少
#[derive(Clone, Debug, Eq, PartialEq)]
struct VirtioCapabilityInfo {
    /// The bar in which the structure can be found.
    bar: u8,
    /// The offset within the bar.
    offset: u32,
    /// The length in bytes of the structure within the bar.
    length: u32,
}

/// An error encountered initialising a VirtIO PCI transport.
/// VirtIO PCI transport 初始化时的错误
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VirtioPciError {
    /// PCI device vender ID was not the VirtIO vendor ID.
    InvalidVendorId(u16),
    /// No valid `VIRTIO_PCI_CAP_COMMON_CFG` capability was found.
    MissingCommonConfig,
    /// No valid `VIRTIO_PCI_CAP_NOTIFY_CFG` capability was found.
    MissingNotifyConfig,
    /// `VIRTIO_PCI_CAP_NOTIFY_CFG` capability has a `notify_off_multiplier` that is not a multiple
    /// of 2.
    InvalidNotifyOffMultiplier(u32),
    /// No valid `VIRTIO_PCI_CAP_ISR_CFG` capability was found.
    MissingIsrConfig,
    /// An IO BAR was provided rather than a memory BAR.
    UnexpectedBarType,
    /// A BAR which we need was not allocated an address.
    BarNotAllocated(u8),
    /// The offset for some capability was greater than the length of the BAR.
    BarOffsetOutOfRange,
    /// The virtual address was not aligned as expected.
    Misaligned {
        /// The virtual address in question.
        vaddr: VirtAddr,
        /// The expected alignment in bytes.
        alignment: usize,
    },
    ///获取虚拟地址失败
    BarGetVaddrFailed,
    /// A generic PCI error,
    Pci(PciError),
}

impl Display for VirtioPciError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::InvalidVendorId(vendor_id) => write!(
                f,
                "PCI device vender ID {:#06x} was not the VirtIO vendor ID {:#06x}.",
                vendor_id, VIRTIO_VENDOR_ID
            ),
            Self::MissingCommonConfig => write!(
                f,
                "No valid `VIRTIO_PCI_CAP_COMMON_CFG` capability was found."
            ),
            Self::MissingNotifyConfig => write!(
                f,
                "No valid `VIRTIO_PCI_CAP_NOTIFY_CFG` capability was found."
            ),
            Self::InvalidNotifyOffMultiplier(notify_off_multiplier) => {
                write!(
                    f,
                    "`VIRTIO_PCI_CAP_NOTIFY_CFG` capability has a `notify_off_multiplier` that is not a multiple of 2: {}",
                    notify_off_multiplier
                )
            }
            Self::MissingIsrConfig => {
                write!(f, "No valid `VIRTIO_PCI_CAP_ISR_CFG` capability was found.")
            }
            Self::UnexpectedBarType => write!(f, "Unexpected BAR (expected memory BAR)."),
            Self::BarNotAllocated(bar_index) => write!(f, "Bar {} not allocated.", bar_index),
            Self::BarOffsetOutOfRange => write!(f, "Capability offset greater than BAR length."),
            Self::Misaligned { vaddr, alignment } => write!(
                f,
                "Virtual address {:?} was not aligned to a {} byte boundary as expected.",
                vaddr, alignment
            ),
            Self::BarGetVaddrFailed => write!(f, "Get bar virtaddress failed"),
            Self::Pci(pci_error) => pci_error.fmt(f),
        }
    }
}

/// PCI error到VirtioPciError的转换，层层上报
impl From<PciError> for VirtioPciError {
    fn from(error: PciError) -> Self {
        Self::Pci(error)
    }
}

/// @brief 获取虚拟地址并将其转化为对应类型的指针
/// @param device_bar 存储bar信息的结构体 struct_info 存储cfg空间的位置信息
/// @return Result<NonNull<T>, VirtioPciError> 成功则返回对应类型的指针，失败则返回Error
fn get_bar_region<T>(
    device_bar: &PciStandardDeviceBar,
    struct_info: &VirtioCapabilityInfo,
) -> Result<NonNull<T>, VirtioPciError> {
    let bar_info = device_bar.get_bar(struct_info.bar)?;
    let (bar_address, bar_size) = bar_info
        .memory_address_size()
        .ok_or(VirtioPciError::UnexpectedBarType)?;
    if bar_address == 0 {
        return Err(VirtioPciError::BarNotAllocated(struct_info.bar));
    }
    if struct_info.offset + struct_info.length > bar_size
        || size_of::<T>() > struct_info.length as usize
    {
        return Err(VirtioPciError::BarOffsetOutOfRange);
    }
    //debug!("Chossed bar ={},used={}",struct_info.bar,struct_info.offset + struct_info.length);
    let vaddr = (bar_info
        .virtual_address()
        .ok_or(VirtioPciError::BarGetVaddrFailed)?)
        + struct_info.offset as usize;
    if !vaddr.data().is_multiple_of(align_of::<T>()) {
        return Err(VirtioPciError::Misaligned {
            vaddr,
            alignment: align_of::<T>(),
        });
    }
    let vaddr = NonNull::new(vaddr.data() as *mut u8).unwrap();
    Ok(vaddr.cast())
}

/// @brief 获取虚拟地址并将其转化为对应类型的切片的指针
/// @param device_bar 存储bar信息的结构体 struct_info 存储cfg空间的位置信息切片的指针
/// @return Result<NonNull<[T]>, VirtioPciError> 成功则返回对应类型的指针切片，失败则返回Error
fn get_bar_region_slice<T>(
    device_bar: &PciStandardDeviceBar,
    struct_info: &VirtioCapabilityInfo,
) -> Result<NonNull<[T]>, VirtioPciError> {
    let ptr = get_bar_region::<T>(device_bar, struct_info)?;
    // let raw_slice =
    //     ptr::slice_from_raw_parts_mut(ptr.as_ptr(), struct_info.length as usize / size_of::<T>());
    Ok(nonnull_slice_from_raw_parts(
        ptr,
        struct_info.length as usize / size_of::<T>(),
    ))
}

fn nonnull_slice_from_raw_parts<T>(data: NonNull<T>, len: usize) -> NonNull<[T]> {
    NonNull::new(ptr::slice_from_raw_parts_mut(data.as_ptr(), len)).unwrap()
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #4：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\filesystem\vfs\mount.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use core::{
    any::Any,
    fmt::Debug,
    hash::Hash,
    sync::atomic::{compiler_fence, Ordering},
};

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use hashbrown::HashMap;
use ida::IdAllocator;
use system_error::SystemError;

use crate::{
    driver::base::device::device_number::DeviceNumber,
    filesystem::{
        page_cache::PageCache,
        vfs::{fcntl::AtFlags, vcore::do_mkdir_at},
    },
    libs::{
        casting::DowncastArc,
        lazy_init::Lazy,
        rwlock::RwLock,
        spinlock::{SpinLock, SpinLockGuard},
    },
    mm::{fault::PageFaultMessage, VmFaultReason},
    process::{
        namespace::mnt::{MntNamespace, MountPropagation},
        ProcessManager,
    },
};

use super::{
    file::FileMode, syscall::ModeType, utils::DName, FilePrivateData, FileSystem, FileType,
    IndexNode, InodeId, Magic, PollableInode, SuperBlock,
};

bitflags! {
    /// Mount flags for filesystem independent mount options
    /// These flags correspond to the MS_* constants in Linux
    ///
    /// Reference: https://code.dragonos.org.cn/xref/linux-6.6.21/include/uapi/linux/mount.h#13
    pub struct MountFlags: u32 {
        /// Mount read-only (MS_RDONLY)
        const RDONLY = 1;
        /// Ignore suid and sgid bits (MS_NOSUID)
        const NOSUID = 2;
        /// Disallow access to device special files (MS_NODEV)
        const NODEV = 4;
        /// Disallow program execution (MS_NOEXEC)
        const NOEXEC = 8;
        /// Writes are synced at once (MS_SYNCHRONOUS)
        const SYNCHRONOUS = 16;
        /// Alter flags of a mounted FS (MS_REMOUNT)
        const REMOUNT = 32;
        /// Allow mandatory locks on an FS (MS_MANDLOCK)
        const MANDLOCK = 64;
        /// Directory modifications are synchronous (MS_DIRSYNC)
        const DIRSYNC = 128;
        /// Do not follow symlinks (MS_NOSYMFOLLOW)
        const NOSYMFOLLOW = 256;
        /// Do not update access times (MS_NOATIME)
        const NOATIME = 1024;
        /// Do not update directory access times (MS_NODIRATIME)
        const NODIRATIME = 2048;
        /// Bind mount (MS_BIND)
        const BIND = 4096;
        /// Move mount (MS_MOVE)
        const MOVE = 8192;
        /// Recursive mount (MS_REC)
        const REC = 16384;
        /// Silent mount (MS_SILENT, deprecated MS_VERBOSE)
        const SILENT = 32768;
        /// VFS does not apply the umask (MS_POSIXACL)
        const POSIXACL = 1 << 16;
        /// Change to unbindable (MS_UNBINDABLE)
        const UNBINDABLE = 1 << 17;
        /// Change to private (MS_PRIVATE)
        const PRIVATE = 1 << 18;
        /// Change to slave (MS_SLAVE)
        const SLAVE = 1 << 19;
        /// Change to shared (MS_SHARED)
        const SHARED = 1 << 20;
        /// Update atime relative to mtime/ctime (MS_RELATIME)
        const RELATIME = 1 << 21;
        /// This is a kern_mount call (MS_KERNMOUNT)
        const KERNMOUNT = 1 << 22;
        /// Update inode I_version field (MS_I_VERSION)
        const I_VERSION = 1 << 23;
        /// Always perform atime updates (MS_STRICTATIME)
        const STRICTATIME = 1 << 24;
        /// Update the on-disk [acm]times lazily (MS_LAZYTIME)
        const LAZYTIME = 1 << 25;
        /// This is a submount (MS_SUBMOUNT)
        const SUBMOUNT = 1 << 26;
        /// Do not allow remote locking (MS_NOREMOTELOCK)
        const NOREMOTELOCK = 1 << 27;
        /// Do not perform security checks (MS_NOSEC)
        const NOSEC = 1 << 28;
        /// This mount has been created by the kernel (MS_BORN)
        const BORN = 1 << 29;
        /// This mount is active (MS_ACTIVE)
        const ACTIVE = 1 << 30;
        /// Mount flags not allowed from userspace (MS_NOUSER)
        const NOUSER = 1 << 31;

        /// Superblock flags that can be altered by MS_REMOUNT
        const RMT_MASK = MountFlags::RDONLY.bits() |
            MountFlags::SYNCHRONOUS.bits() |
            MountFlags::MANDLOCK.bits() |
            MountFlags::I_VERSION.bits() |
            MountFlags::LAZYTIME.bits();

        /// Old magic mount flag and mask
        const MGC_VAL = 0xC0ED0000; // Magic value for mount flags
        const MGC_MASK = 0xFFFF0000; // Mask for magic mount flags
    }
}

impl MountFlags {
    /// Convert mount flags to a comma-separated string representation
    ///
    /// This function converts MountFlags to a string format similar to /proc/mounts,
    /// such as "rw,nosuid,nodev,noexec,relatime".
    ///
    /// # Returns
    ///
    /// A String containing the mount options in comma-separated format.
    #[inline(never)]
    pub fn options_string(&self) -> String {
        let mut options = Vec::new();

        // Check read/write flag
        if self.contains(MountFlags::RDONLY) {
            options.push("ro");
        } else {
            options.push("rw");
        }

        // Check other flags
        if self.contains(MountFlags::NOSUID) {
            options.push("nosuid");
        }
        if self.contains(MountFlags::NODEV) {
            options.push("nodev");
        }
        if self.contains(MountFlags::NOEXEC) {
            options.push("noexec");
        }
        if self.contains(MountFlags::SYNCHRONOUS) {
            options.push("sync");
        }
        if self.contains(MountFlags::MANDLOCK) {
            options.push("mand");
        }
        if self.contains(MountFlags::DIRSYNC) {
            options.push("dirsync");
        }
        if self.contains(MountFlags::NOSYMFOLLOW) {
            options.push("nosymfollow");
        }
        if self.contains(MountFlags::NOATIME) {
            options.push("noatime");
        }
        if self.contains(MountFlags::NODIRATIME) {
            options.push("nodiratime");
        }
        if self.contains(MountFlags::RELATIME) {
            options.push("relatime");
        }
        if self.contains(MountFlags::STRICTATIME) {
            options.push("strictatime");
        }
        if self.contains(MountFlags::LAZYTIME) {
            options.push("lazytime");
        }

        // Mount propagation flags
        if self.contains(MountFlags::UNBINDABLE) {
            options.push("unbindable");
        }
        if self.contains(MountFlags::PRIVATE) {
            options.push("private");
        }
        if self.contains(MountFlags::SLAVE) {
            options.push("slave");
        }
        if self.contains(MountFlags::SHARED) {
            options.push("shared");
        }

        // Internal flags (typically not shown in /proc/mounts)
        // We'll skip flags like BIND, MOVE, REC, REMOUNT, etc. as they're
        // not typically displayed in mount options

        options.join(",")
    }
}

// MountId类型
int_like!(MountId, usize);

static MOUNT_ID_ALLOCATOR: SpinLock<IdAllocator> =
    SpinLock::new(IdAllocator::new(0, usize::MAX).unwrap());

impl MountId {
    fn alloc() -> Self {
        let id = MOUNT_ID_ALLOCATOR.lock().alloc().unwrap();

        MountId(id)
    }

    unsafe fn free(&mut self) {
        MOUNT_ID_ALLOCATOR.lock().free(self.0);
    }
}

const MOUNTFS_BLOCK_SIZE: u64 = 512;
const MOUNTFS_MAX_NAMELEN: u64 = 64;
/// @brief 挂载文件系统
/// 挂载文件系统的时候，套了MountFS这一层，以实现文件系统的递归挂载
pub struct MountFS {
    // MountFS内部的文件系统
    inner_filesystem: Arc<dyn FileSystem>,
    /// 用来存储InodeID->挂载点的MountFS的B树
    mountpoints: SpinLock<BTreeMap<InodeId, Arc<MountFS>>>,
    /// 当前文件系统挂载到的那个挂载点的Inode
    self_mountpoint: RwLock<Option<Arc<MountFSInode>>>,
    /// 指向当前MountFS的弱引用
    self_ref: Weak<MountFS>,

    namespace: Lazy<Weak<MntNamespace>>,
    propagation: Arc<MountPropagation>,
    mount_id: MountId,

    mount_flags: MountFlags,
}

impl Debug for MountFS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountFS")
            .field("mount_id", &self.mount_id)
            .finish()
    }
}

impl PartialEq for MountFS {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.self_ref(), &other.self_ref())
    }
}

impl Hash for MountFS {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.mount_id.hash(state);
    }
}

impl Eq for MountFS {}

/// @brief MountFS的Index Node 注意，这个IndexNode只是一个中间层。它的目的是将具体文件系统的Inode与挂载机制连接在一起。
#[derive(Debug)]
#[cast_to([sync] IndexNode)]
pub struct MountFSInode {
    /// 当前挂载点对应到具体的文件系统的Inode
    inner_inode: Arc<dyn IndexNode>,
    /// 当前Inode对应的MountFS
    mount_fs: Arc<MountFS>,
    /// 指向自身的弱引用
    self_ref: Weak<MountFSInode>,
}

impl MountFS {
    pub fn new(
        inner_filesystem: Arc<dyn FileSystem>,
        self_mountpoint: Option<Arc<MountFSInode>>,
        propagation: Arc<MountPropagation>,
        mnt_ns: Option<&Arc<MntNamespace>>,
        mount_flags: MountFlags,
    ) -> Arc<Self> {
        let result = Arc::new_cyclic(|self_ref| MountFS {
            inner_filesystem,
            mountpoints: SpinLock::new(BTreeMap::new()),
            self_mountpoint: RwLock::new(self_mountpoint),
            self_ref: self_ref.clone(),
            namespace: Lazy::new(),
            propagation,
            mount_id: MountId::alloc(),
            mount_flags,
        });

        if let Some(mnt_ns) = mnt_ns {
            result.set_namespace(Arc::downgrade(mnt_ns));
        }

        result
    }

    pub fn deepcopy(&self, self_mountpoint: Option<Arc<MountFSInode>>) -> Arc<Self> {
        let mountfs = Arc::new_cyclic(|self_ref| MountFS {
            inner_filesystem: self.inner_filesystem.clone(),
            mountpoints: SpinLock::new(BTreeMap::new()),
            self_mountpoint: RwLock::new(self_mountpoint),
            self_ref: self_ref.clone(),
            namespace: Lazy::new(),
            propagation: self.propagation.clone(),
            mount_id: MountId::alloc(),
            mount_flags: self.mount_flags,
        });

        return mountfs;
    }

    pub fn mount_flags(&self) -> MountFlags {
        self.mount_flags
    }

    pub fn add_mount(&self, inode_id: InodeId, mount_fs: Arc<MountFS>) -> Result<(), SystemError> {
        // 检查是否已经存在同名的挂载点
        if self.mountpoints.lock().contains_key(&inode_id) {
            return Err(SystemError::EEXIST);
        }

        // 将新的挂载点添加到当前MountFS的挂载点列表中
        self.mountpoints.lock().insert(inode_id, mount_fs.clone());

        Ok(())
    }

    pub fn mountpoints(&self) -> SpinLockGuard<'_, BTreeMap<InodeId, Arc<MountFS>>> {
        self.mountpoints.lock()
    }

    pub fn propagation(&self) -> Arc<MountPropagation> {
        self.propagation.clone()
    }

    pub fn set_namespace(&self, namespace: Weak<MntNamespace>) {
        self.namespace.init(namespace);
    }

    pub fn fs_type(&self) -> &str {
        self.inner_filesystem.name()
    }

    #[inline(never)]
    pub fn self_mountpoint(&self) -> Option<Arc<MountFSInode>> {
        self.self_mountpoint.read().as_ref().cloned()
    }

    /// @brief 用Arc指针包裹MountFS对象。
    /// 本函数的主要功能为，初始化MountFS对象中的自引用Weak指针
    /// 本函数只应在构造器中被调用
    #[allow(dead_code)]
    #[deprecated]
    fn wrap(self) -> Arc<Self> {
        // 创建Arc指针
        let mount_fs: Arc<MountFS> = Arc::new(self);
        // 创建weak指针
        let weak: Weak<MountFS> = Arc::downgrade(&mount_fs);

        // 将Arc指针转为Raw指针并对其内部的self_ref字段赋值
        let ptr: *mut MountFS = mount_fs.as_ref() as *const Self as *mut Self;
        unsafe {
            (*ptr).self_ref = weak;
            // 返回初始化好的MountFS对象
            return mount_fs;
        }
    }

    /// @brief 获取挂载点的文件系统的root inode
    pub fn mountpoint_root_inode(&self) -> Arc<MountFSInode> {
        return Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode: self.inner_filesystem.root_inode(),
            mount_fs: self.self_ref.upgrade().unwrap(),
            self_ref: self_ref.clone(),
        });
    }

    pub fn inner_filesystem(&self) -> Arc<dyn FileSystem> {
        return self.inner_filesystem.clone();
    }

    pub fn self_ref(&self) -> Arc<Self> {
        self.self_ref.upgrade().unwrap()
    }

    /// 卸载文件系统
    /// # Errors
    /// 如果当前文件系统是根文件系统，那么将会返回`EINVAL`
    pub fn umount(&self) -> Result<Arc<MountFS>, SystemError> {
        let r = self
            .self_mountpoint()
            .ok_or(SystemError::EINVAL)?
            .do_umount();

        self.self_mountpoint.write().take();

        return r;
    }
}

impl Drop for MountFS {
    fn drop(&mut self) {
        // 释放MountId
        unsafe {
            self.mount_id.free();
        }
    }
}

impl MountFSInode {
    /// @brief 用Arc指针包裹MountFSInode对象。
    /// 本函数的主要功能为，初始化MountFSInode对象中的自引用Weak指针
    /// 本函数只应在构造器中被调用
    #[allow(dead_code)]
    #[deprecated]
    fn wrap(self) -> Arc<Self> {
        // 创建Arc指针
        let inode: Arc<MountFSInode> = Arc::new(self);
        // 创建Weak指针
        let weak: Weak<MountFSInode> = Arc::downgrade(&inode);
        // 将Arc指针转为Raw指针并对其内部的self_ref字段赋值
        compiler_fence(Ordering::SeqCst);
        let ptr: *mut MountFSInode = inode.as_ref() as *const Self as *mut Self;
        compiler_fence(Ordering::SeqCst);
        unsafe {
            (*ptr).self_ref = weak;
            compiler_fence(Ordering::SeqCst);

            // 返回初始化好的MountFSInode对象
            return inode;
        }
    }

    /// @brief 判断当前inode是否为它所在的文件系统的root inode
    fn is_mountpoint_root(&self) -> Result<bool, SystemError> {
        return Ok(self.inner_inode.fs().root_inode().metadata()?.inode_id
            == self.inner_inode.metadata()?.inode_id);
    }

    /// @brief 在挂载树上进行inode替换。
    /// 如果当前inode是父MountFS内的一个挂载点，那么，本函数将会返回挂载到这个挂载点下的文件系统的root inode.
    /// 如果当前inode在父MountFS内，但不是挂载点，那么说明在这里不需要进行inode替换，因此直接返回当前inode。
    ///
    /// @return Arc<MountFSInode>
    fn overlaid_inode(&self) -> Arc<MountFSInode> {
        // 某些情况下，底层 inode 可能已被删除或失效，此时 metadata() 可能返回错误
        // 为避免因 unwrap 导致内核 panic，这里将错误视作“非挂载点”，直接返回自身
        let inode_id = match self.metadata() {
            Ok(md) => md.inode_id,
            Err(e) => {
                log::warn!(
                    "MountFSInode::overlaid_inode: metadata() failed: {:?}; treat as non-mountpoint",
                    e
                );
                return self.self_ref.upgrade().unwrap();
            }
        };

        if let Some(sub_mountfs) = self.mount_fs.mountpoints.lock().get(&inode_id) {
            return sub_mountfs.mountpoint_root_inode();
        } else {
            return self.self_ref.upgrade().unwrap();
        }
    }

    fn do_find(&self, name: &str) -> Result<Arc<MountFSInode>, SystemError> {
        // 直接调用当前inode所在的文件系统的find方法进行查找
        // 由于向下查找可能会跨越文件系统的边界，因此需要尝试替换inode
        let inner_inode = self.inner_inode.find(name)?;
        return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode,
            mount_fs: self.mount_fs.clone(),
            self_ref: self_ref.clone(),
        })
        .overlaid_inode());
    }

    pub(super) fn do_parent(&self) -> Result<Arc<MountFSInode>, SystemError> {
        if self.is_mountpoint_root()? {
            // 当前inode是它所在的文件系统的root inode
            match self.mount_fs.self_mountpoint() {
                Some(inode) => {
                    let inner_inode = inode.parent()?;
                    return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
                        inner_inode,
                        mount_fs: self.mount_fs.clone(),
                        self_ref: self_ref.clone(),
                    }));
                }
                None => {
                    return Ok(self.self_ref.upgrade().unwrap());
                }
            }
        } else {
            let inner_inode = self.inner_inode.parent()?;
            // 向上查找时，不会跨过文件系统的边界，因此直接调用当前inode所在的文件系统的find方法进行查找
            return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
                inner_inode,
                mount_fs: self.mount_fs.clone(),
                self_ref: self_ref.clone(),
            }));
        }
    }

    /// 移除挂载点下的文件系统
    fn do_umount(&self) -> Result<Arc<MountFS>, SystemError> {
        if self.metadata()?.file_type != FileType::Dir {
            return Err(SystemError::ENOTDIR);
        }
        return self
            .mount_fs
            .mountpoints
            .lock()
            .remove(&self.inner_inode.metadata()?.inode_id)
            .ok_or(SystemError::ENOENT);
    }

    #[inline(never)]
    fn do_absolute_path(&self) -> Result<String, SystemError> {
        let mut current = self.self_ref.upgrade().unwrap();

        // For special inode, we can directly get the absolute path
        if let Ok(p) = current.inner_inode.absolute_path() {
            return Ok(p);
        }

        let mut path_parts = Vec::new();
        let root_inode = ProcessManager::current_mntns().root_inode();
        let inode_id = root_inode.metadata()?.inode_id;
        while current.metadata()?.inode_id != inode_id {
            let name = current.dname()?;
            path_parts.push(name.0);

            // 防循环检查：如果路径深度超过1024，抛出警告
            if path_parts.len() > 1024 {
                #[inline(never)]
                fn __log_warn(root: usize, cur: usize) {
                    log::warn!(
                        "Path depth exceeds 1024, possible infinite loop. root: {}, cur: {}",
                        root,
                        cur
                    );
                }
                __log_warn(inode_id.data(), current.metadata().unwrap().inode_id.data());
                return Err(SystemError::ELOOP);
            }

            current = current.do_parent()?;
        }

        // 由于我们从叶子节点向上遍历到根节点，所以需要反转路径部分
        path_parts.reverse();

        // 构建最终的绝对路径字符串
        let mut absolute_path = String::with_capacity(
            path_parts.iter().map(|s| s.len()).sum::<usize>() + path_parts.len(),
        );
        for part in path_parts {
            absolute_path.push('/');
            absolute_path.push_str(&part);
        }

        Ok(absolute_path)
    }

    pub fn clone_with_new_mount_fs(&self, mount_fs: Arc<MountFS>) -> Arc<MountFSInode> {
        Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode: self.inner_inode.clone(),
            mount_fs,
            self_ref: self_ref.clone(),
        })
    }
}

impl IndexNode for MountFSInode {
    fn open(
        &self,
        data: SpinLockGuard<FilePrivateData>,
        mode: &FileMode,
    ) -> Result<(), SystemError> {
        return self.inner_inode.open(data, mode);
    }

    fn close(&self, data: SpinLockGuard<FilePrivateData>) -> Result<(), SystemError> {
        self.inner_inode.close(data)
    }

    fn create_with_data(
        &self,
        name: &str,
        file_type: FileType,
        mode: ModeType,
        data: usize,
    ) -> Result<Arc<dyn IndexNode>, SystemError> {
        let inner_inode = self
            .inner_inode
            .create_with_data(name, file_type, mode, data)?;
        return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode,
            mount_fs: self.mount_fs.clone(),
            self_ref: self_ref.clone(),
        }));
    }

    fn truncate(&self, len: usize) -> Result<(), SystemError> {
        return self.inner_inode.truncate(len);
    }

    fn read_at(
        &self,
        offset: usize,
        len: usize,
        buf: &mut [u8],
        data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        return self.inner_inode.read_at(offset, len, buf, data);
    }

    fn write_at(
        &self,
        offset: usize,
        len: usize,
        buf: &[u8],
        data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        return self.inner_inode.write_at(offset, len, buf, data);
    }

    fn read_direct(
        &self,
        offset: usize,
        len: usize,
        buf: &mut [u8],
        data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        self.inner_inode.read_direct(offset, len, buf, data)
    }

    fn write_direct(
        &self,
        offset: usize,
        len: usize,
        buf: &[u8],
        data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize, SystemError> {
        self.inner_inode.write_direct(offset, len, buf, data)
    }

    #[inline]
    fn fs(&self) -> Arc<dyn FileSystem> {
        return self.mount_fs.clone();
    }

    #[inline]
    fn as_any_ref(&self) -> &dyn core::any::Any {
        return self.inner_inode.as_any_ref();
    }

    #[inline]
    fn metadata(&self) -> Result<super::Metadata, SystemError> {
        return self.inner_inode.metadata();
    }

    #[inline]
    fn set_metadata(&self, metadata: &super::Metadata) -> Result<(), SystemError> {
        return self.inner_inode.set_metadata(metadata);
    }

    #[inline]
    fn resize(&self, len: usize) -> Result<(), SystemError> {
        return self.inner_inode.resize(len);
    }

    #[inline]
    fn create(
        &self,
        name: &str,
        file_type: FileType,
        mode: ModeType,
    ) -> Result<Arc<dyn IndexNode>, SystemError> {
        let inner_inode = self.inner_inode.create(name, file_type, mode)?;
        return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode,
            mount_fs: self.mount_fs.clone(),
            self_ref: self_ref.clone(),
        }));
    }

    fn link(&self, name: &str, other: &Arc<dyn IndexNode>) -> Result<(), SystemError> {
        return self.inner_inode.link(name, other);
    }

    /// @brief 在挂载文件系统中删除文件/文件夹
    #[inline]
    fn unlink(&self, name: &str) -> Result<(), SystemError> {
        let inode_id = self.inner_inode.find(name)?.metadata()?.inode_id;

        // 先检查这个inode是否为一个挂载点，如果当前inode是一个挂载点，那么就不能删除这个inode
        if self.mount_fs.mountpoints.lock().contains_key(&inode_id) {
            return Err(SystemError::EBUSY);
        }
        // 调用内层的inode的方法来删除这个inode
        return self.inner_inode.unlink(name);
    }

    #[inline]
    fn rmdir(&self, name: &str) -> Result<(), SystemError> {
        let inode_id = self.inner_inode.find(name)?.metadata()?.inode_id;

        // 先检查这个inode是否为一个挂载点，如果当前inode是一个挂载点，那么就不能删除这个inode
        if self.mount_fs.mountpoints.lock().contains_key(&inode_id) {
            return Err(SystemError::EBUSY);
        }
        // 调用内层的rmdir的方法来删除这个inode
        let r = self.inner_inode.rmdir(name);

        return r;
    }

    #[inline]
    fn move_to(
        &self,
        old_name: &str,
        target: &Arc<dyn IndexNode>,
        new_name: &str,
    ) -> Result<(), SystemError> {
        return self.inner_inode.move_to(old_name, target, new_name);
    }

    fn find(&self, name: &str) -> Result<Arc<dyn IndexNode>, SystemError> {
        match name {
            // 查找的是当前目录
            "" | "." => self
                .self_ref
                .upgrade()
                .map(|inode| inode as Arc<dyn IndexNode>)
                .ok_or(SystemError::ENOENT),
            // 往父级查找
            ".." => self.parent(),
            // 在当前目录下查找
            // 直接调用当前inode所在的文件系统的find方法进行查找
            // 由于向下查找可能会跨越文件系统的边界，因此需要尝试替换inode
            _ => self.do_find(name).map(|inode| inode as Arc<dyn IndexNode>),
        }
    }

    #[inline]
    fn get_entry_name(&self, ino: InodeId) -> Result<alloc::string::String, SystemError> {
        return self.inner_inode.get_entry_name(ino);
    }

    #[inline]
    fn get_entry_name_and_metadata(
        &self,
        ino: InodeId,
    ) -> Result<(alloc::string::String, super::Metadata), SystemError> {
        return self.inner_inode.get_entry_name_and_metadata(ino);
    }

    #[inline]
    fn ioctl(
        &self,
        cmd: u32,
        data: usize,
        private_data: &FilePrivateData,
    ) -> Result<usize, SystemError> {
        return self.inner_inode.ioctl(cmd, data, private_data);
    }

    #[inline]
    fn list(&self) -> Result<alloc::vec::Vec<alloc::string::String>, SystemError> {
        return self.inner_inode.list();
    }

    fn mount(
        &self,
        fs: Arc<dyn FileSystem>,
        mount_flags: MountFlags,
    ) -> Result<Arc<MountFS>, SystemError> {
        let metadata = self.inner_inode.metadata()?;
        if metadata.file_type != FileType::Dir {
            return Err(SystemError::ENOTDIR);
        }

        if self.is_mountpoint_root()? {
            return Err(SystemError::EBUSY);
        }

        // 若已有挂载系统，保证MountFS只包一层
        let to_mount_fs = fs
            .clone()
            .downcast_arc::<MountFS>()
            .map(|it| it.inner_filesystem())
            .unwrap_or(fs);

        let new_mount_fs = MountFS::new(
            to_mount_fs,
            Some(self.self_ref.upgrade().unwrap()),
            MountPropagation::new_private(), // 暂时不支持传播，后续会补充完善挂载传播性
            Some(&ProcessManager::current_mntns()),
            mount_flags,
        );
        self.mount_fs
            .add_mount(metadata.inode_id, new_mount_fs.clone())?;

        let mount_path = self.absolute_path();
        let mount_path = Arc::new(MountPath::from(mount_path?));
        ProcessManager::current_mntns().add_mount(
            Some(metadata.inode_id),
            mount_path,
            new_mount_fs.clone(),
        )?;

        return Ok(new_mount_fs);
    }

    fn mount_from(&self, from: Arc<dyn IndexNode>) -> Result<Arc<MountFS>, SystemError> {
        let metadata = self.metadata()?;
        if from.metadata()?.file_type != FileType::Dir || metadata.file_type != FileType::Dir {
            return Err(SystemError::ENOTDIR);
        }
        if self.is_mountpoint_root()? {
            return Err(SystemError::EBUSY);
        }
        // debug!("from {:?}, to {:?}", from, self);
        let new_mount_fs = from.umount()?;
        self.mount_fs
            .add_mount(metadata.inode_id, new_mount_fs.clone())?;
        // 更新当前挂载点的self_mountpoint
        new_mount_fs
            .self_mountpoint
            .write()
            .replace(self.self_ref.upgrade().unwrap());
        let mntns = ProcessManager::current_mntns();

        let mount_path = mntns
            .mount_list()
            .get_mount_path_by_mountfs(&new_mount_fs)
            .unwrap_or_else(|| {
                panic!(
                    "MountFS::mount_from: failed to get mount path for {:?}",
                    self.mount_fs.name()
                );
            });

        mntns.mount_list().remove(mount_path.as_str());
        ProcessManager::current_mntns()
            .add_mount(Some(metadata.inode_id), mount_path, new_mount_fs.clone())
            .expect("MountFS::mount_from: failed to add mount.");
        return Ok(new_mount_fs);
    }

    fn umount(&self) -> Result<Arc<MountFS>, SystemError> {
        if !self.is_mountpoint_root()? {
            return Err(SystemError::EINVAL);
        }
        return self.mount_fs.umount();
    }

    fn absolute_path(&self) -> Result<String, SystemError> {
        self.do_absolute_path()
    }

    #[inline]
    fn mknod(
        &self,
        filename: &str,
        mode: ModeType,
        dev_t: DeviceNumber,
    ) -> Result<Arc<dyn IndexNode>, SystemError> {
        let inner_inode = self.inner_inode.mknod(filename, mode, dev_t)?;
        return Ok(Arc::new_cyclic(|self_ref| MountFSInode {
            inner_inode,
            mount_fs: self.mount_fs.clone(),
            self_ref: self_ref.clone(),
        }));
    }

    #[inline]
    fn special_node(&self) -> Option<super::SpecialNodeData> {
        self.inner_inode.special_node()
    }

    /// 若不支持，则调用第二种情况来从父目录获取文件名
    /// # Performance
    /// 应尽可能引入DName，
    /// 在默认情况下，性能非常差！！！
    fn dname(&self) -> Result<DName, SystemError> {
        if self.is_mountpoint_root()? {
            if let Some(inode) = self.mount_fs.self_mountpoint() {
                return inode.inner_inode.dname();
            }
        }
        return self.inner_inode.dname();
    }

    fn parent(&self) -> Result<Arc<dyn IndexNode>, SystemError> {
        return self.do_parent().map(|inode| inode as Arc<dyn IndexNode>);
    }

    fn page_cache(&self) -> Option<Arc<PageCache>> {
        self.inner_inode.page_cache()
    }

    fn as_pollable_inode(&self) -> Result<&dyn PollableInode, SystemError> {
        self.inner_inode.as_pollable_inode()
    }

    fn read_sync(&self, offset: usize, buf: &mut [u8]) -> Result<usize, SystemError> {
        self.inner_inode.read_sync(offset, buf)
    }

    fn write_sync(&self, offset: usize, buf: &[u8]) -> Result<usize, SystemError> {
        self.inner_inode.write_sync(offset, buf)
    }

    fn getxattr(&self, name: &str, buf: &mut [u8]) -> Result<usize, SystemError> {
        self.inner_inode.getxattr(name, buf)
    }

    fn setxattr(&self, name: &str, value: &[u8]) -> Result<usize, SystemError> {
        self.inner_inode.setxattr(name, value)
    }
}

impl FileSystem for MountFS {
    fn root_inode(&self) -> Arc<dyn IndexNode> {
        match self.self_mountpoint() {
            Some(inode) => return inode.mount_fs.root_inode(),
            // 当前文件系统是rootfs
            None => self.mountpoint_root_inode(),
        }
    }

    fn info(&self) -> super::FsInfo {
        return self.inner_filesystem.info();
    }

    /// @brief 本函数用于实现动态转换。
    /// 具体的文件系统在实现本函数时，最简单的方式就是：直接返回self
    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        self.inner_filesystem.name()
    }
    fn super_block(&self) -> SuperBlock {
        SuperBlock::new(Magic::MOUNT_MAGIC, MOUNTFS_BLOCK_SIZE, MOUNTFS_MAX_NAMELEN)
    }

    unsafe fn fault(&self, pfm: &mut PageFaultMessage) -> VmFaultReason {
        self.inner_filesystem.fault(pfm)
    }

    unsafe fn map_pages(
        &self,
        pfm: &mut PageFaultMessage,
        start_pgoff: usize,
        end_pgoff: usize,
    ) -> VmFaultReason {
        self.inner_filesystem.map_pages(pfm, start_pgoff, end_pgoff)
    }
}

/// MountList
/// ```rust
/// use alloc::collection::BTreeSet;
/// let map = BTreeSet::from([
///     "/sys", "/dev", "/", "/bin", "/proc"
/// ]);
/// assert_eq!(format!("{:?}", map), "{\"/\", \"/bin\", \"/dev\", \"/proc\", \"/sys\"}");
/// // {"/", "/bin", "/dev", "/proc", "/sys"}
/// ```
#[derive(PartialEq, Eq, Debug, Hash)]
pub struct MountPath(String);

impl From<&str> for MountPath {
    fn from(value: &str) -> Self {
        Self(String::from(value))
    }
}

impl From<String> for MountPath {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl AsRef<str> for MountPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialOrd for MountPath {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MountPath {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let self_dep = self.0.chars().filter(|c| *c == '/').count();
        let othe_dep = other.0.chars().filter(|c| *c == '/').count();
        if self_dep == othe_dep {
            // 深度一样时反序来排
            // 根目录和根目录下的文件的绝对路径都只有一个'/'
            other.0.cmp(&self.0)
        } else {
            // 根据深度，深度
            othe_dep.cmp(&self_dep)
        }
    }
}

impl MountPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// 维护一个挂载点的记录，以支持特定于文件系统的索引
pub struct MountList {
    inner: RwLock<InnerMountList>,
}

struct InnerMountList {
    mounts: HashMap<Arc<MountPath>, Arc<MountFS>>,
    mfs2ino: HashMap<Arc<MountFS>, InodeId>,
    ino2mp: HashMap<InodeId, Arc<MountPath>>,
}

impl MountList {
    /// # new - 创建新的MountList实例
    ///
    /// 创建一个空的挂载点列表。
    ///
    /// ## 返回值
    ///
    /// - `MountList`: 新的挂载点列表实例
    pub fn new() -> Arc<Self> {
        Arc::new(MountList {
            inner: RwLock::new(InnerMountList {
                mounts: HashMap::new(),
                ino2mp: HashMap::new(),
                mfs2ino: HashMap::new(),
            }),
        })
    }

    /// Inserts a filesystem mount point into the mount list.
    ///
    /// This function adds a new filesystem mount point to the mount list. If a mount point
    /// already exists at the specified path, it will be updated with the new filesystem.
    ///
    /// # Thread Safety
    /// This function is thread-safe as it uses a RwLock to ensure safe concurrent access.
    ///
    /// # Arguments
    /// * `ino` - An optional InodeId representing the inode of the `fs` mounted at.
    /// * `path` - The mount path where the filesystem will be mounted
    /// * `fs` - The filesystem instance to be mounted at the specified path
    #[inline(never)]
    pub fn insert(&self, ino: Option<InodeId>, path: Arc<MountPath>, fs: Arc<MountFS>) {
        let mut inner = self.inner.write();
        inner.mounts.insert(path.clone(), fs.clone());
        // 如果不是根目录挂载点，则记录inode到挂载点的映射
        if let Some(ino) = ino {
            inner.ino2mp.insert(ino, path.clone());
            inner.mfs2ino.insert(fs, ino);
        }
    }

    /// # get_mount_point - 获取挂载点的路径
    ///
    /// 这个函数用于查找给定路径的挂载点。它搜索一个内部映射，找到与路径匹配的挂载点。
    ///
    /// ## 参数
    ///
    /// - `path: T`: 这是一个可转换为字符串的引用，表示要查找其挂载点的路径。
    ///
    /// ## 返回值
    ///
    /// - `Option<(String, String, Arc<MountFS>)>`:
    ///   - `Some((mount_point, rest_path, fs))`: 如果找到了匹配的挂载点，返回一个包含挂载点路径、剩余路径和挂载文件系统的元组。
    ///   - `None`: 如果没有找到匹配的挂载点，返回 None。
    #[inline(never)]
    #[allow(dead_code)]
    pub fn get_mount_point<T: AsRef<str>>(
        &self,
        path: T,
    ) -> Option<(Arc<MountPath>, String, Arc<MountFS>)> {
        self.inner
            .upgradeable_read()
            .mounts
            .iter()
            .filter_map(|(key, fs)| {
                let strkey = key.as_str();
                if let Some(rest) = path.as_ref().strip_prefix(strkey) {
                    return Some((key.clone(), rest.to_string(), fs.clone()));
                }
                None
            })
            .next()
    }

    /// # remove - 移除挂载点
    ///
    /// 从挂载点管理器中移除一个挂载点。
    ///
    /// 此函数用于从挂载点管理器中移除一个已经存在的挂载点。如果挂载点不存在，则不进行任何操作。
    ///
    /// ## 参数
    ///
    /// - `path: T`: `T` 实现了 `Into<MountPath>`  trait，代表要移除的挂载点的路径。
    ///
    /// ## 返回值
    ///
    /// - `Option<Arc<MountFS>>`: 返回一个 `Arc<MountFS>` 类型的可选值，表示被移除的挂载点，如果挂载点不存在则返回 `None`。
    #[inline(never)]
    pub fn remove<T: Into<MountPath>>(&self, path: T) -> Option<Arc<MountFS>> {
        let mut inner = self.inner.write();
        let path: MountPath = path.into();
        // 从挂载点列表中移除指定路径的挂载点
        if let Some(fs) = inner.mounts.remove(&path) {
            if let Some(ino) = inner.mfs2ino.remove(&fs) {
                inner.ino2mp.remove(&ino);
            }
            return Some(fs);
        }
        None
    }

    /// # clone_inner - 克隆内部挂载点列表
    pub fn clone_inner(&self) -> HashMap<Arc<MountPath>, Arc<MountFS>> {
        self.inner.read().mounts.clone()
    }

    #[inline(never)]
    pub fn get_mount_path_by_ino(&self, ino: InodeId) -> Option<Arc<MountPath>> {
        self.inner.read().ino2mp.get(&ino).cloned()
    }

    #[inline(never)]
    pub fn get_mount_path_by_mountfs(&self, mountfs: &Arc<MountFS>) -> Option<Arc<MountPath>> {
        let inner = self.inner.read();
        inner
            .mfs2ino
            .get(mountfs)
            .and_then(|ino| inner.ino2mp.get(ino).cloned())
    }
}

impl Debug for MountList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let inner = self.inner.read();
        f.debug_map().entries(inner.mounts.iter()).finish()
    }
}

/// 判断给定的inode是否为其所在文件系统的根inode
///
/// ## 返回值
///
/// - `true`: 是根inode
/// - `false`: 不是根inode或者传入的inode不是MountFSInode类型，或者调用inode的metadata方法时报错了。
pub fn is_mountpoint_root(inode: &Arc<dyn IndexNode>) -> bool {
    let mnt_inode = inode.as_any_ref().downcast_ref::<MountFSInode>();
    if let Some(mnt) = mnt_inode {
        return mnt.is_mountpoint_root().unwrap_or(false);
    }

    return false;
}

/// # do_mount_mkdir - 在指定挂载点创建目录并挂载文件系统
///
/// 在指定的挂载点创建一个目录，并将其挂载到文件系统中。如果挂载点已经存在，并且不是空的，
/// 则会返回错误。成功时，会返回一个新的挂载文件系统的引用。
///
/// ## 参数
///
/// - `fs`: FileSystem - 文件系统的引用，用于创建和挂载目录。
/// - `mount_point`: &str - 挂载点路径，用于创建和挂载目录。
///
/// ## 返回值
///
/// - `Ok(Arc<MountFS>)`: 成功挂载文件系统后，返回挂载文件系统的共享引用。
/// - `Err(SystemError)`: 挂载失败时，返回系统错误。
pub fn do_mount_mkdir(
    fs: Arc<dyn FileSystem>,
    mount_point: &str,
    mount_flags: MountFlags,
) -> Result<Arc<MountFS>, SystemError> {
    let inode = do_mkdir_at(
        AtFlags::AT_FDCWD.bits(),
        mount_point,
        FileMode::from_bits_truncate(0o755),
    )?;
    let result = ProcessManager::current_mntns().get_mount_point(mount_point);
    if let Some((_, rest, _fs)) = result {
        if rest.is_empty() {
            return Err(SystemError::EBUSY);
        }
    }
    return inode.mount(fs, mount_flags);
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #5：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\mm\page.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use alloc::{string::ToString, vec::Vec};
use core::{
    fmt::{self, Debug, Error, Formatter},
    marker::PhantomData,
    mem,
    ops::Add,
    sync::atomic::{compiler_fence, Ordering},
};
use system_error::SystemError;
use unified_init::macros::unified_init;

use alloc::sync::Arc;
use hashbrown::{HashMap, HashSet};
use log::{error, info};
use lru::LruCache;

use crate::{
    arch::{interrupt::ipi::send_ipi, mm::LockedFrameAllocator, MMArch},
    exception::ipi::{IpiKind, IpiTarget},
    filesystem::{page_cache::PageCache, vfs::FilePrivateData},
    init::initcall::INITCALL_CORE,
    libs::{
        rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard},
        spinlock::{SpinLock, SpinLockGuard},
    },
    process::{ProcessControlBlock, ProcessManager},
    time::{sleep::nanosleep, PosixTimeSpec},
};

use super::{
    allocator::page_frame::{
        deallocate_page_frames, FrameAllocator, PageFrameCount, PhysPageFrame,
    },
    syscall::ProtFlags,
    ucontext::LockedVMA,
    MemoryManagementArch, PageTableKind, PhysAddr, VirtAddr,
};

pub const PAGE_4K_SHIFT: usize = 12;
#[allow(dead_code)]
pub const PAGE_2M_SHIFT: usize = 21;
pub const PAGE_1G_SHIFT: usize = 30;

pub const PAGE_4K_SIZE: usize = 1 << PAGE_4K_SHIFT;
pub const PAGE_2M_SIZE: usize = 1 << PAGE_2M_SHIFT;

/// 全局物理页信息管理器
pub static mut PAGE_MANAGER: Option<SpinLock<PageManager>> = None;

/// 初始化PAGE_MANAGER
pub fn page_manager_init() {
    info!("page_manager_init");
    let page_manager = SpinLock::new(PageManager::new());

    compiler_fence(Ordering::SeqCst);
    unsafe { PAGE_MANAGER = Some(page_manager) };
    compiler_fence(Ordering::SeqCst);

    info!("page_manager_init done");
}

pub fn page_manager_lock_irqsave() -> SpinLockGuard<'static, PageManager> {
    unsafe { PAGE_MANAGER.as_ref().unwrap().lock_irqsave() }
}

// 物理页管理器
pub struct PageManager {
    phys2page: HashMap<PhysAddr, Arc<Page>>,
}

impl PageManager {
    pub fn new() -> Self {
        Self {
            phys2page: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn contains(&self, paddr: &PhysAddr) -> bool {
        self.phys2page.contains_key(paddr)
    }

    pub fn get(&mut self, paddr: &PhysAddr) -> Option<Arc<Page>> {
        if let Some(p) = page_reclaimer_lock_irqsave().get(paddr) {
            return Some(p);
        }
        self.phys2page.get(paddr).cloned()
    }

    pub fn get_unwrap(&mut self, paddr: &PhysAddr) -> Arc<Page> {
        if let Some(p) = page_reclaimer_lock_irqsave().get(paddr) {
            return p;
        }
        self.phys2page
            .get(paddr)
            .unwrap_or_else(|| panic!("Phys Page not found, {:?}", paddr))
            .clone()
    }

    fn insert(&mut self, page: &Arc<Page>) -> Result<Arc<Page>, SystemError> {
        let phys = page.phys_address();
        if !self.phys2page.contains_key(&phys) {
            self.phys2page.insert(phys, page.clone());
            Ok(page.clone())
        } else {
            log::error!("phys page: {phys:?} already exists.");
            Err(SystemError::EINVAL)
        }
    }

    pub fn remove_page(&mut self, paddr: &PhysAddr) {
        self.phys2page.remove(paddr);
    }

    /// # 创建一个新页面并加入管理器
    ///
    /// ## 参数
    ///
    /// - `shared`: 是否共享
    /// - `page_type`: 页面类型
    /// - `flags`: 页面标志
    /// - `allocator`: 物理页帧分配器
    ///
    /// ## 返回值
    ///
    /// - `Ok(Arc<Page>)`: 新页面
    /// - `Err(SystemError)`: 错误码
    pub fn create_one_page(
        &mut self,
        page_type: PageType,
        flags: PageFlags,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<Arc<Page>, SystemError> {
        self.create_pages(page_type, flags, allocator, PageFrameCount::ONE)?
            .1
            .first()
            .ok_or(SystemError::ENOMEM)
            .cloned()
    }

    /// # 创建新页面并加入管理器
    ///
    /// ## 参数
    ///
    /// - `shared`: 是否共享
    /// - `page_type`: 页面类型
    /// - `flags`: 页面标志
    /// - `allocator`: 物理页帧分配器
    /// - `count`: 页面数量
    ///
    /// ## 返回值
    ///
    /// - `Ok((PhysAddr, Vec<Arc<Page>>))`: 页面起始物理地址，新页面集合
    /// - `Err(SystemError)`: 错误码
    pub fn create_pages(
        &mut self,
        page_type: PageType,
        flags: PageFlags,
        allocator: &mut dyn FrameAllocator,
        count: PageFrameCount,
    ) -> Result<(PhysAddr, Vec<Arc<Page>>), SystemError> {
        compiler_fence(Ordering::SeqCst);
        let (start_paddr, count) = unsafe { allocator.allocate(count).ok_or(SystemError::ENOMEM)? };
        compiler_fence(Ordering::SeqCst);

        unsafe {
            let vaddr = MMArch::phys_2_virt(start_paddr).unwrap();
            MMArch::write_bytes(vaddr, 0, MMArch::PAGE_SIZE * count.data());
        }

        let mut cur_phys = PhysPageFrame::new(start_paddr);
        let mut ret: Vec<Arc<Page>> = Vec::new();
        for _ in 0..count.data() {
            let page = Page::new(cur_phys.phys_address(), page_type.clone(), flags);
            if let Err(e) = self.insert(&page) {
                for insert_page in ret {
                    self.remove_page(&insert_page.read_irqsave().phys_addr);
                }
                return Err(e);
            }
            ret.push(page);
            cur_phys = cur_phys.next();
        }
        Ok((start_paddr, ret))
    }

    /// # 拷贝管理器中原有页面并加入管理器，同时拷贝原页面内容
    ///
    /// ## 参数
    ///
    /// - `old_phys`: 原页面的物理地址
    /// - `allocator`: 物理页帧分配器
    ///
    /// ## 返回值
    ///
    /// - `Ok(Arc<Page>)`: 新页面
    /// - `Err(SystemError)`: 错误码
    pub fn copy_page(
        &mut self,
        old_phys: &PhysAddr,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<Arc<Page>, SystemError> {
        let old_page = self.get(old_phys).ok_or(SystemError::EINVAL)?;
        let paddr = unsafe { allocator.allocate_one().ok_or(SystemError::ENOMEM)? };

        assert!(!self.contains(&paddr), "phys page: {paddr:?} already exist");

        let page = Page::copy(old_page.read_irqsave(), paddr)
            .inspect_err(|_| unsafe { allocator.free_one(paddr) })?;

        self.insert(&page)?;

        Ok(page)
    }
}

pub static mut PAGE_RECLAIMER: Option<SpinLock<PageReclaimer>> = None;

pub fn page_reclaimer_init() {
    info!("page_reclaimer_init");
    let page_reclaimer = SpinLock::new(PageReclaimer::new());

    compiler_fence(Ordering::SeqCst);
    unsafe { PAGE_RECLAIMER = Some(page_reclaimer) };
    compiler_fence(Ordering::SeqCst);

    info!("page_reclaimer_init done");
}

/// 页面回收线程
static mut PAGE_RECLAIMER_THREAD: Option<Arc<ProcessControlBlock>> = None;

/// 页面回收线程初始化函数
#[unified_init(INITCALL_CORE)]
fn page_reclaimer_thread_init() -> Result<(), SystemError> {
    let closure = crate::process::kthread::KernelThreadClosure::StaticEmptyClosure((
        &(page_reclaim_thread as fn() -> i32),
        (),
    ));
    let pcb = crate::process::kthread::KernelThreadMechanism::create_and_run(
        closure,
        "page_reclaim".to_string(),
    )
    .ok_or("")
    .expect("create tty_refresh thread failed");
    unsafe {
        PAGE_RECLAIMER_THREAD = Some(pcb);
    }
    Ok(())
}

/// 页面回收线程执行的函数
fn page_reclaim_thread() -> i32 {
    loop {
        let usage = unsafe { LockedFrameAllocator.usage() };
        // log::info!("usage{:?}", usage);

        // 保留4096个页面，总计16MB的空闲空间
        if usage.free().data() < 4096 {
            let page_to_free = 4096;
            page_reclaimer_lock_irqsave().shrink_list(PageFrameCount::new(page_to_free));
        } else {
            //TODO 暂时让页面回收线程负责脏页回写任务，后续需要分离
            page_reclaimer_lock_irqsave().flush_dirty_pages();
            // 休眠5秒
            // log::info!("sleep");
            let _ = nanosleep(PosixTimeSpec::new(0, 500_000_000));
        }
    }
}

/// 获取页面回收器
pub fn page_reclaimer_lock_irqsave() -> SpinLockGuard<'static, PageReclaimer> {
    unsafe { PAGE_RECLAIMER.as_ref().unwrap().lock_irqsave() }
}

/// 页面回收器
pub struct PageReclaimer {
    lru: LruCache<PhysAddr, Arc<Page>>,
}

impl PageReclaimer {
    pub fn new() -> Self {
        Self {
            lru: LruCache::unbounded(),
        }
    }

    pub fn get(&mut self, paddr: &PhysAddr) -> Option<Arc<Page>> {
        self.lru.get(paddr).cloned()
    }

    pub fn insert_page(&mut self, paddr: PhysAddr, page: &Arc<Page>) {
        self.lru.put(paddr, page.clone());
    }

    pub fn remove_page(&mut self, paddr: &PhysAddr) -> Option<Arc<Page>> {
        self.lru.pop(paddr)
    }

    /// lru链表缩减
    /// ## 参数
    ///
    /// - `count`: 需要缩减的页面数量
    pub fn shrink_list(&mut self, count: PageFrameCount) {
        for _ in 0..count.data() {
            let (_, page) = self.lru.pop_lru().expect("pagecache is empty");
            let mut guard = page.write_irqsave();
            if let PageType::File(info) = guard.page_type().clone() {
                let page_cache = &info.page_cache;
                let page_index = info.index;
                let paddr = guard.phys_address();
                if guard.flags().contains(PageFlags::PG_DIRTY) {
                    // 先回写脏页
                    Self::page_writeback(&mut guard, true);
                }

                // 删除页面
                page_cache.lock_irqsave().remove_page(page_index);
                page_manager_lock_irqsave().remove_page(&paddr);
                self.remove_page(&paddr);
            }
        }
    }

    /// 唤醒页面回收线程
    pub fn wakeup_claim_thread() {
        // log::info!("wakeup_claim_thread");
        let _ = ProcessManager::wakeup(unsafe { PAGE_RECLAIMER_THREAD.as_ref().unwrap() });
    }

    /// 脏页回写函数
    /// ## 参数
    ///
    /// - `guard`: 需要回写的脏页
    /// - `unmap`: 是否取消映射
    ///
    /// ## 返回值
    /// - VmFaultReason: 页面错误处理信息标志
    pub fn page_writeback(guard: &mut RwLockWriteGuard<InnerPage>, unmap: bool) {
        // log::debug!("page writeback: {:?}", guard.phys_addr);

        let (page_cache, page_index) = match guard.page_type() {
            PageType::File(info) => (info.page_cache.clone(), info.index),
            _ => {
                log::warn!("try to writeback a non-file page");
                return;
            }
        };
        let paddr = guard.phys_address();
        let inode = page_cache.inode().clone().unwrap().upgrade().unwrap();

        for vma in guard.vma_set() {
            let address_space = vma.lock_irqsave().address_space().and_then(|x| x.upgrade());
            if address_space.is_none() {
                continue;
            }
            let address_space = address_space.unwrap();
            let mut guard = address_space.write();
            let mapper = &mut guard.user_mapper.utable;
            let virt = vma.lock_irqsave().page_address(page_index).unwrap();
            if unmap {
                unsafe {
                    // 取消页表映射
                    mapper.unmap(virt, false).unwrap().flush();
                }
            } else {
                unsafe {
                    // 保护位设为只读
                    mapper.remap(
                        virt,
                        mapper.get_entry(virt, 0).unwrap().flags().set_write(false),
                    )
                };
            }
        }

        let len = if let Ok(metadata) = inode.metadata() {
            let size = metadata.size as usize;
            size.saturating_sub(page_index * MMArch::PAGE_SIZE)
        } else {
            MMArch::PAGE_SIZE
        };

        if len > 0 {
            inode
                .write_direct(
                    page_index * MMArch::PAGE_SIZE,
                    len,
                    unsafe {
                        core::slice::from_raw_parts(
                            MMArch::phys_2_virt(paddr).unwrap().data() as *mut u8,
                            len,
                        )
                    },
                    SpinLock::new(FilePrivateData::Unused).lock(),
                )
                .unwrap();
        }

        // 清除标记
        guard.remove_flags(PageFlags::PG_DIRTY);
    }

    /// lru脏页刷新
    pub fn flush_dirty_pages(&mut self) {
        // log::info!("flush_dirty_pages");
        let iter = self.lru.iter();
        for (_paddr, page) in iter {
            let mut guard = page.write_irqsave();
            if guard.flags().contains(PageFlags::PG_DIRTY) {
                Self::page_writeback(&mut guard, false);
            }
        }
    }
}

bitflags! {
    pub struct PageFlags: u64 {
        const PG_LOCKED = 1 << 0;
        const PG_WRITEBACK = 1 << 1;
        const PG_REFERENCED = 1 << 2;
        const PG_UPTODATE = 1 << 3;
        const PG_DIRTY = 1 << 4;
        const PG_LRU = 1 << 5;
        const PG_HEAD = 1 << 6;
        const PG_WAITERS = 1 << 7;
        const PG_ACTIVE = 1 << 8;
        const PG_WORKINGSET = 1 << 9;
        const PG_ERROR = 1 << 10;
        const PG_SLAB = 1 << 11;
        const PG_RESERVED = 1 << 14;
        const PG_PRIVATE = 1 << 15;
        const PG_RECLAIM = 1 << 18;
        const PG_SWAPBACKED = 1 << 19;
        const PG_UNEVICTABLE = 1 << 20;
    }
}

#[derive(Debug)]
pub struct Page {
    inner: RwLock<InnerPage>,
    /// 页面所在物理地址
    phys_addr: PhysAddr,
}

impl Page {
    /// # 创建新页面
    ///
    /// ## 参数
    ///
    /// - `shared`: 是否共享
    /// - `phys_addr`: 物理地址
    /// - `page_type`: 页面类型
    /// - `flags`: 页面标志
    ///
    /// ## 返回值
    ///
    /// - `Arc<Page>`: 新页面
    fn new(phys_addr: PhysAddr, page_type: PageType, flags: PageFlags) -> Arc<Page> {
        let inner = InnerPage::new(phys_addr, page_type, flags);
        let page = Arc::new(Self {
            inner: RwLock::new(inner),
            phys_addr,
        });
        if page.read_irqsave().flags == PageFlags::PG_LRU {
            page_reclaimer_lock_irqsave().insert_page(phys_addr, &page);
        };
        page
    }

    /// # 拷贝页面及内容
    ///
    /// ## 参数
    ///
    /// - `old_guard`: 源页面的读守卫
    /// - `new_phys`: 新页面的物理地址
    ///
    /// ## 返回值
    ///
    /// - `Ok(Arc<Page>)`: 新页面
    /// - `Err(SystemError)`: 错误码
    fn copy(
        old_guard: RwLockReadGuard<InnerPage>,
        new_phys: PhysAddr,
    ) -> Result<Arc<Page>, SystemError> {
        let page_type = old_guard.page_type().clone();
        let flags = *old_guard.flags();
        let inner = InnerPage::new(new_phys, page_type, flags);
        unsafe {
            let old_vaddr =
                MMArch::phys_2_virt(old_guard.phys_address()).ok_or(SystemError::EFAULT)?;
            let new_vaddr = MMArch::phys_2_virt(new_phys).ok_or(SystemError::EFAULT)?;
            (new_vaddr.data() as *mut u8)
                .copy_from_nonoverlapping(old_vaddr.data() as *mut u8, MMArch::PAGE_SIZE);
        }
        Ok(Arc::new(Self {
            inner: RwLock::new(inner),
            phys_addr: new_phys,
        }))
    }

    #[inline(always)]
    pub fn phys_address(&self) -> PhysAddr {
        self.phys_addr
    }

    pub fn read_irqsave(&self) -> RwLockReadGuard<'_, InnerPage> {
        self.inner.read_irqsave()
    }

    pub fn write_irqsave(&self) -> RwLockWriteGuard<'_, InnerPage> {
        self.inner.write_irqsave()
    }
}

#[derive(Debug)]
/// 物理页面信息
pub struct InnerPage {
    /// 映射到当前page的VMA
    vma_set: HashSet<Arc<LockedVMA>>,
    /// 标志
    flags: PageFlags,
    /// 页面所在物理地址
    phys_addr: PhysAddr,
    /// 页面类型
    page_type: PageType,
}

impl InnerPage {
    pub fn new(phys_addr: PhysAddr, page_type: PageType, flags: PageFlags) -> Self {
        Self {
            vma_set: HashSet::new(),
            flags,
            phys_addr,
            page_type,
        }
    }

    /// 将vma加入anon_vma
    pub fn insert_vma(&mut self, vma: Arc<LockedVMA>) {
        self.vma_set.insert(vma);
    }

    /// 将vma从anon_vma中删去
    pub fn remove_vma(&mut self, vma: &LockedVMA) {
        self.vma_set.remove(vma);
    }

    /// 判断当前物理页是否能被回
    pub fn can_deallocate(&self) -> bool {
        self.map_count() == 0 && !self.flags.contains(PageFlags::PG_UNEVICTABLE)
    }

    pub fn shared(&self) -> bool {
        self.map_count() > 1
    }

    pub fn page_cache(&self) -> Option<Arc<PageCache>> {
        match &self.page_type {
            PageType::File(info) => Some(info.page_cache.clone()),
            _ => None,
        }
    }

    pub fn page_type(&self) -> &PageType {
        &self.page_type
    }

    pub fn set_page_type(&mut self, page_type: PageType) {
        self.page_type = page_type;
    }

    #[inline(always)]
    pub fn vma_set(&self) -> &HashSet<Arc<LockedVMA>> {
        &self.vma_set
    }

    #[inline(always)]
    pub fn map_count(&self) -> usize {
        self.vma_set.len()
    }

    #[inline(always)]
    pub fn flags(&self) -> &PageFlags {
        &self.flags
    }

    #[inline(always)]
    pub fn set_flags(&mut self, flags: PageFlags) {
        self.flags = flags
    }

    #[inline(always)]
    pub fn add_flags(&mut self, flags: PageFlags) {
        self.flags = self.flags.union(flags);
    }

    #[inline(always)]
    pub fn remove_flags(&mut self, flags: PageFlags) {
        self.flags = self.flags.difference(flags);
    }

    #[inline(always)]
    fn phys_address(&self) -> PhysAddr {
        self.phys_addr
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(
            MMArch::phys_2_virt(self.phys_addr).unwrap().data() as *const u8,
            MMArch::PAGE_SIZE,
        )
    }

    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(
            MMArch::phys_2_virt(self.phys_addr).unwrap().data() as *mut u8,
            MMArch::PAGE_SIZE,
        )
    }

    pub unsafe fn copy_from_slice(&mut self, slice: &[u8]) {
        assert_eq!(
            slice.len(),
            MMArch::PAGE_SIZE,
            "length of slice not match PAGE_SIZE"
        );
        core::slice::from_raw_parts_mut(
            MMArch::phys_2_virt(self.phys_addr).unwrap().data() as *mut u8,
            MMArch::PAGE_SIZE,
        )
        .copy_from_slice(slice);
    }

    pub unsafe fn truncate(&mut self, len: usize) {
        if len > MMArch::PAGE_SIZE {
            return;
        }

        let vaddr = unsafe { MMArch::phys_2_virt(self.phys_addr).unwrap() };

        unsafe {
            core::slice::from_raw_parts_mut(
                (vaddr.data() + len) as *mut u8,
                MMArch::PAGE_SIZE - len,
            )
            .fill(0)
        };
    }
}

impl Drop for InnerPage {
    fn drop(&mut self) {
        assert!(
            self.map_count() == 0,
            "page drop when map count is non-zero"
        );

        unsafe {
            deallocate_page_frames(PhysPageFrame::new(self.phys_addr), PageFrameCount::new(1))
        };
    }
}

/// 页面类型，包含额外的页面信息
#[derive(Debug, Clone)]
pub enum PageType {
    /// 普通页面，不含额外信息
    Normal,
    /// 文件映射页，含文件映射相关信息
    File(FileMapInfo),
    /// 共享内存页，记录ShmId
    Shm,
}

#[derive(Debug, Clone)]
pub struct FileMapInfo {
    pub page_cache: Arc<PageCache>,
    /// 在pagecache中的偏移
    pub index: usize,
}

#[derive(Debug)]
pub struct PageTable<Arch> {
    /// 当前页表表示的虚拟地址空间的起始地址
    base: VirtAddr,
    /// 当前页表所在的物理地址
    phys: PhysAddr,
    /// 当前页表的层级（请注意，最顶级页表的level为[Arch::PAGE_LEVELS - 1]）
    level: usize,
    phantom: PhantomData<Arch>,
}

#[allow(dead_code)]
impl<Arch: MemoryManagementArch> PageTable<Arch> {
    pub unsafe fn new(base: VirtAddr, phys: PhysAddr, level: usize) -> Self {
        Self {
            base,
            phys,
            level,
            phantom: PhantomData,
        }
    }

    /// 获取顶级页表
    ///
    /// ## 参数
    ///
    /// - table_kind 页表类型
    ///
    /// ## 返回值
    ///
    /// 返回顶级页表
    pub unsafe fn top_level_table(table_kind: PageTableKind) -> Self {
        return Self::new(
            VirtAddr::new(0),
            Arch::table(table_kind),
            Arch::PAGE_LEVELS - 1,
        );
    }

    /// 获取当前页表的物理地址
    #[inline(always)]
    pub fn phys(&self) -> PhysAddr {
        self.phys
    }

    /// 当前页表表示的虚拟地址空间的起始地址
    #[inline(always)]
    pub fn base(&self) -> VirtAddr {
        self.base
    }

    /// 获取当前页表的层级
    #[inline(always)]
    pub fn level(&self) -> usize {
        self.level
    }

    /// 获取当前页表自身所在的虚拟地址
    #[inline(always)]
    pub unsafe fn virt(&self) -> VirtAddr {
        return Arch::phys_2_virt(self.phys).unwrap();
    }

    /// 获取第i个页表项所表示的虚拟内存空间的起始地址
    pub fn entry_base(&self, i: usize) -> Option<VirtAddr> {
        if i < Arch::PAGE_ENTRY_NUM {
            let shift = self.level * Arch::PAGE_ENTRY_SHIFT + Arch::PAGE_SHIFT;
            return Some(self.base.add(i << shift));
        } else {
            return None;
        }
    }

    /// 获取当前页表的第i个页表项所在的虚拟地址（注意与entry_base进行区分）
    pub unsafe fn entry_virt(&self, i: usize) -> Option<VirtAddr> {
        if i < Arch::PAGE_ENTRY_NUM {
            return Some(self.virt().add(i * Arch::PAGE_ENTRY_SIZE));
        } else {
            return None;
        }
    }

    /// 获取当前页表的第i个页表项
    pub unsafe fn entry(&self, i: usize) -> Option<PageEntry<Arch>> {
        let entry_virt = self.entry_virt(i)?;
        return Some(PageEntry::from_usize(Arch::read::<usize>(entry_virt)));
    }

    /// 设置当前页表的第i个页表项
    pub unsafe fn set_entry(&self, i: usize, entry: PageEntry<Arch>) -> Option<()> {
        let entry_virt = self.entry_virt(i)?;
        Arch::write::<usize>(entry_virt, entry.data());
        return Some(());
    }

    /// 判断当前页表的第i个页表项是否已经填写了值
    ///
    /// ## 参数
    /// - Some(true) 如果已经填写了值
    /// - Some(false) 如果未填写值
    /// - None 如果i超出了页表项的范围
    pub fn entry_mapped(&self, i: usize) -> Option<bool> {
        let etv = unsafe { self.entry_virt(i) }?;
        if unsafe { Arch::read::<usize>(etv) } != 0 {
            return Some(true);
        } else {
            return Some(false);
        }
    }

    /// 根据虚拟地址，获取对应的页表项在页表中的下标
    ///
    /// ## 参数
    ///
    /// - addr: 虚拟地址
    ///
    /// ## 返回值
    ///
    /// 页表项在页表中的下标。如果addr不在当前页表所表示的虚拟地址空间中，则返回None
    pub fn index_of(&self, addr: VirtAddr) -> Option<usize> {
        let addr = VirtAddr::new(addr.data() & Arch::PAGE_ADDRESS_MASK);
        let shift = self.level * Arch::PAGE_ENTRY_SHIFT + Arch::PAGE_SHIFT;

        let mask = (MMArch::PAGE_ENTRY_NUM << shift) - 1;
        if addr < self.base || addr >= self.base.add(mask) {
            return None;
        } else {
            return Some((addr.data() >> shift) & MMArch::PAGE_ENTRY_MASK);
        }
    }

    /// 获取第i个页表项指向的下一级页表
    pub unsafe fn next_level_table(&self, index: usize) -> Option<Self> {
        if self.level == 0 {
            return None;
        }

        // 返回下一级页表
        return Some(PageTable::new(
            self.entry_base(index)?,
            self.entry(index)?.address().ok()?,
            self.level - 1,
        ));
    }

    /// 拷贝页表
    /// ## 参数
    ///
    /// - `allocator`: 物理页框分配器
    /// - `copy_on_write`: 是否写时复制
    pub unsafe fn clone(
        &self,
        allocator: &mut impl FrameAllocator,
        copy_on_write: bool,
    ) -> Option<PageTable<Arch>> {
        // 分配新页面作为新的页表
        let phys = allocator.allocate_one()?;
        let frame = MMArch::phys_2_virt(phys).unwrap();
        MMArch::write_bytes(frame, 0, MMArch::PAGE_SIZE);
        let new_table = PageTable::new(self.base, phys, self.level);
        if self.level == 0 {
            for i in 0..Arch::PAGE_ENTRY_NUM {
                if let Some(mut entry) = self.entry(i) {
                    if entry.present() {
                        if copy_on_write {
                            let mut new_flags = entry.flags().set_write(false);
                            entry.set_flags(new_flags);
                            self.set_entry(i, entry);
                            new_flags = new_flags.set_dirty(false);
                            entry.set_flags(new_flags);
                            new_table.set_entry(i, entry);
                        } else {
                            let phys = allocator.allocate_one()?;
                            let mut page_manager_guard = page_manager_lock_irqsave();
                            let old_phys = entry.address().unwrap();
                            page_manager_guard.copy_page(&old_phys, allocator).ok()?;
                            new_table.set_entry(i, PageEntry::new(phys, entry.flags()));
                        }
                    }
                }
            }
        } else {
            // 非一级页表拷贝时，对每个页表项对应的页表都进行拷贝
            for i in 0..MMArch::PAGE_ENTRY_NUM {
                if let Some(next_table) = self.next_level_table(i) {
                    let table = next_table.clone(allocator, copy_on_write)?;
                    let old_entry = self.entry(i).unwrap();
                    let entry = PageEntry::new(table.phys(), old_entry.flags());
                    new_table.set_entry(i, entry);
                }
            }
        }
        Some(new_table)
    }
}

/// 页表项
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct PageEntry<Arch> {
    data: usize,
    phantom: PhantomData<Arch>,
}

impl<Arch> Debug for PageEntry<Arch> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_fmt(format_args!("PageEntry({:#x})", self.data))
    }
}

impl<Arch: MemoryManagementArch> PageEntry<Arch> {
    #[inline(always)]
    pub fn new(paddr: PhysAddr, flags: EntryFlags<Arch>) -> Self {
        Self {
            data: MMArch::make_entry(paddr, flags.data()),
            phantom: PhantomData,
        }
    }
    #[inline(always)]
    pub fn from_usize(data: usize) -> Self {
        Self {
            data,
            phantom: PhantomData,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.data
    }

    /// 获取当前页表项指向的物理地址
    ///
    /// ## 返回值
    ///
    /// - Ok(PhysAddr) 如果当前页面存在于物理内存中, 返回物理地址
    /// - Err(PhysAddr) 如果当前页表项不存在, 返回物理地址
    #[inline(always)]
    pub fn address(&self) -> Result<PhysAddr, PhysAddr> {
        let paddr: PhysAddr = {
            #[cfg(target_arch = "x86_64")]
            {
                PhysAddr::new(self.data & Arch::PAGE_ADDRESS_MASK)
            }

            #[cfg(target_arch = "riscv64")]
            {
                let ppn = ((self.data & (!((1 << 10) - 1))) >> 10) & ((1 << 54) - 1);
                super::allocator::page_frame::PhysPageFrame::from_ppn(ppn).phys_address()
            }

            #[cfg(target_arch = "loongarch64")]
            {
                todo!("la64: PageEntry::address")
            }
        };

        if self.present() {
            Ok(paddr)
        } else {
            Err(paddr)
        }
    }

    #[inline(always)]
    pub fn flags(&self) -> EntryFlags<Arch> {
        unsafe { EntryFlags::from_data(self.data & Arch::ENTRY_FLAGS_MASK) }
    }

    #[inline(always)]
    pub fn set_flags(&mut self, flags: EntryFlags<Arch>) {
        self.data = (self.data & !Arch::ENTRY_FLAGS_MASK) | flags.data();
    }

    #[inline(always)]
    pub fn present(&self) -> bool {
        return self.data & Arch::ENTRY_FLAG_PRESENT != 0;
    }

    #[inline(always)]
    pub fn empty(&self) -> bool {
        self.data & !(Arch::ENTRY_FLAG_DIRTY & Arch::ENTRY_FLAG_ACCESSED) == 0
    }

    #[inline(always)]
    pub fn protnone(&self) -> bool {
        return self.data & (Arch::ENTRY_FLAG_PRESENT | Arch::ENTRY_FLAG_GLOBAL)
            == Arch::ENTRY_FLAG_GLOBAL;
    }

    #[inline(always)]
    pub fn write(&self) -> bool {
        return self.data & Arch::ENTRY_FLAG_READWRITE != 0;
    }
}

/// 页表项的标志位
#[derive(Copy, Clone, Hash)]
pub struct EntryFlags<Arch> {
    data: usize,
    phantom: PhantomData<Arch>,
}

impl<Arch: MemoryManagementArch> Default for EntryFlags<Arch> {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl<Arch: MemoryManagementArch> EntryFlags<Arch> {
    #[inline(always)]
    pub fn new() -> Self {
        let mut r = unsafe {
            Self::from_data(
                Arch::ENTRY_FLAG_DEFAULT_PAGE
                    | Arch::ENTRY_FLAG_READONLY
                    | Arch::ENTRY_FLAG_NO_EXEC,
            )
        };

        #[cfg(target_arch = "x86_64")]
        {
            if crate::arch::mm::X86_64MMArch::is_xd_reserved() {
                r = r.set_execute(true);
            }
        }

        return r;
    }

    /// 根据ProtFlags生成EntryFlags
    ///
    /// ## 参数
    ///
    /// - prot_flags: 页的保护标志
    /// - user: 用户空间是否可访问
    pub fn from_prot_flags(prot_flags: ProtFlags, user: bool) -> Self {
        if Arch::PAGE_FAULT_ENABLED {
            let vm_flags = super::VmFlags::from(prot_flags);
            Arch::vm_get_page_prot(vm_flags).set_user(user)
        } else {
            EntryFlags::new()
                .set_user(user)
                .set_execute(prot_flags.contains(ProtFlags::PROT_EXEC))
                .set_write(prot_flags.contains(ProtFlags::PROT_WRITE))
        }
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.data
    }

    #[inline(always)]
    pub const unsafe fn from_data(data: usize) -> Self {
        return Self {
            data,
            phantom: PhantomData,
        };
    }

    /// 为新页表的页表项设置默认值
    ///
    /// 默认值为：
    /// - present
    /// - read only
    /// - kernel space
    /// - no exec
    #[inline(always)]
    pub fn new_page_table(user: bool) -> Self {
        return unsafe {
            let r = {
                #[cfg(target_arch = "x86_64")]
                {
                    Self::from_data(Arch::ENTRY_FLAG_DEFAULT_TABLE | Arch::ENTRY_FLAG_READWRITE)
                }

                #[cfg(target_arch = "riscv64")]
                {
                    // riscv64指向下一级页表的页表项，不应设置R/W/X权限位
                    Self::from_data(Arch::ENTRY_FLAG_DEFAULT_TABLE)
                }

                #[cfg(target_arch = "loongarch64")]
                {
                    Self::from_data(Arch::ENTRY_FLAG_DEFAULT_TABLE)
                }
            };

            #[cfg(target_arch = "x86_64")]
            {
                if user {
                    r.set_user(true)
                } else {
                    r
                }
            }

            #[cfg(target_arch = "riscv64")]
            {
                r
            }

            #[cfg(target_arch = "loongarch64")]
            {
                todo!("loongarch64: new_page_table")
            }
        };
    }

    /// 取得当前页表项的所有权，更新当前页表项的标志位，并返回更新后的页表项。
    ///
    /// ## 参数
    /// - flag 要更新的标志位的值
    /// - value 如果为true，那么将flag对应的位设置为1，否则设置为0
    ///
    /// ## 返回值
    ///
    /// 更新后的页表项
    #[inline(always)]
    #[must_use]
    pub fn update_flags(mut self, flag: usize, value: bool) -> Self {
        if value {
            self.data |= flag;
        } else {
            self.data &= !flag;
        }
        return self;
    }

    /// 判断当前页表项是否存在指定的flag（只有全部flag都存在才返回true）
    #[inline(always)]
    pub fn has_flag(&self, flag: usize) -> bool {
        return self.data & flag == flag;
    }

    #[inline(always)]
    pub fn present(&self) -> bool {
        return self.has_flag(Arch::ENTRY_FLAG_PRESENT);
    }

    /// 设置当前页表项的权限
    ///
    /// @param value 如果为true，那么将当前页表项的权限设置为用户态可访问
    #[must_use]
    #[inline(always)]
    pub fn set_user(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_USER, value);
    }

    /// 用户态是否可以访问当前页表项
    #[inline(always)]
    pub fn has_user(&self) -> bool {
        return self.has_flag(Arch::ENTRY_FLAG_USER);
    }

    /// 设置当前页表项的可写性, 如果为true，那么将当前页表项的权限设置为可写, 否则设置为只读
    ///
    /// ## 返回值
    ///
    /// 更新后的页表项.
    ///
    /// **请注意，**本函数会取得当前页表项的所有权，因此返回的页表项不是原来的页表项
    #[must_use]
    #[inline(always)]
    pub fn set_write(self, value: bool) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            // 有的架构同时具有可写和不可写的标志位，因此需要同时更新
            return self
                .update_flags(Arch::ENTRY_FLAG_READONLY, !value)
                .update_flags(Arch::ENTRY_FLAG_READWRITE, value);
        }

        #[cfg(target_arch = "riscv64")]
        {
            if value {
                return self.update_flags(Arch::ENTRY_FLAG_READWRITE, true);
            } else {
                return self
                    .update_flags(Arch::ENTRY_FLAG_READONLY, true)
                    .update_flags(Arch::ENTRY_FLAG_WRITEABLE, false);
            }
        }

        #[cfg(target_arch = "loongarch64")]
        {
            todo!("la64: set_write")
        }
    }

    /// 当前页表项是否可写
    #[inline(always)]
    pub fn has_write(&self) -> bool {
        // 有的架构同时具有可写和不可写的标志位，因此需要同时判断
        return self.data & (Arch::ENTRY_FLAG_READWRITE | Arch::ENTRY_FLAG_READONLY)
            == Arch::ENTRY_FLAG_READWRITE;
    }

    /// 设置当前页表项的可执行性, 如果为true，那么将当前页表项的权限设置为可执行, 否则设置为不可执行
    #[must_use]
    #[inline(always)]
    pub fn set_execute(self, mut value: bool) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            // 如果xd位被保留，那么将可执行性设置为true
            if crate::arch::mm::X86_64MMArch::is_xd_reserved() {
                value = true;
            }
        }

        // 有的架构同时具有可执行和不可执行的标志位，因此需要同时更新
        return self
            .update_flags(Arch::ENTRY_FLAG_NO_EXEC, !value)
            .update_flags(Arch::ENTRY_FLAG_EXEC, value);
    }

    /// 当前页表项是否可执行
    #[inline(always)]
    pub fn has_execute(&self) -> bool {
        // 有的架构同时具有可执行和不可执行的标志位，因此需要同时判断
        return self.data & (Arch::ENTRY_FLAG_EXEC | Arch::ENTRY_FLAG_NO_EXEC)
            == Arch::ENTRY_FLAG_EXEC;
    }

    /// 设置当前页表项的缓存策略
    ///
    /// ## 参数
    ///
    /// - value: 如果为true，那么将当前页表项的缓存策略设置为不缓存。
    #[inline(always)]
    pub fn set_page_cache_disable(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_CACHE_DISABLE, value);
    }

    /// 获取当前页表项的缓存策略
    ///
    /// ## 返回值
    ///
    /// 如果当前页表项的缓存策略为不缓存，那么返回true，否则返回false。
    #[inline(always)]
    pub fn has_page_cache_disable(&self) -> bool {
        return self.has_flag(Arch::ENTRY_FLAG_CACHE_DISABLE);
    }

    /// 设置当前页表项的写穿策略
    ///
    /// ## 参数
    ///
    /// - value: 如果为true，那么将当前页表项的写穿策略设置为写穿。
    #[inline(always)]
    pub fn set_page_write_through(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_WRITE_THROUGH, value);
    }

    #[inline(always)]
    pub fn set_page_global(self, value: bool) -> Self {
        return self.update_flags(MMArch::ENTRY_FLAG_GLOBAL, value);
    }

    /// 获取当前页表项的写穿策略
    ///
    /// ## 返回值
    ///
    /// 如果当前页表项的写穿策略为写穿，那么返回true，否则返回false。
    #[inline(always)]
    pub fn has_page_write_through(&self) -> bool {
        return self.has_flag(Arch::ENTRY_FLAG_WRITE_THROUGH);
    }

    /// 设置当前页表是否为脏页
    ///
    /// ## 参数
    ///
    /// - value: 如果为true，那么将当前页表项的写穿策略设置为写穿。
    #[inline(always)]
    pub fn set_dirty(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_DIRTY, value);
    }

    /// 设置当前页表被访问
    ///
    /// ## 参数
    ///
    /// - value: 如果为true，那么将当前页表项的访问标志设置为已访问。
    #[inline(always)]
    pub fn set_access(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_ACCESSED, value);
    }

    /// 设置指向的页是否为大页
    ///
    /// ## 参数
    ///
    /// - value: 如果为true，那么将当前页表项的访问标志设置为已访问。
    #[inline(always)]
    pub fn set_huge_page(self, value: bool) -> Self {
        return self.update_flags(Arch::ENTRY_FLAG_HUGE_PAGE, value);
    }

    /// MMIO内存的页表项标志
    #[inline(always)]
    pub fn mmio_flags() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::new()
                .set_user(false)
                .set_write(true)
                .set_execute(true)
                .set_page_cache_disable(true)
                .set_page_write_through(true)
                .set_page_global(true)
        }

        #[cfg(target_arch = "riscv64")]
        {
            Self::new()
                .set_user(false)
                .set_write(true)
                .set_execute(true)
                .set_page_global(true)
        }

        #[cfg(target_arch = "loongarch64")]
        {
            todo!("la64: mmio_flags()")
        }
    }
}

impl<Arch: MemoryManagementArch> fmt::Debug for EntryFlags<Arch> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryFlags")
            .field("bits", &format_args!("{:#0x}", self.data))
            .field("present", &self.present())
            .field("has_write", &self.has_write())
            .field("has_execute", &self.has_execute())
            .field("has_user", &self.has_user())
            .finish()
    }
}

/// 页表映射器
#[derive(Hash)]
pub struct PageMapper<Arch, F> {
    /// 页表类型
    table_kind: PageTableKind,
    /// 根页表物理地址
    table_paddr: PhysAddr,
    /// 页分配器
    frame_allocator: F,
    phantom: PhantomData<fn() -> Arch>,
}

impl<Arch: MemoryManagementArch, F: FrameAllocator> PageMapper<Arch, F> {
    /// 创建新的页面映射器
    ///
    /// ## 参数
    /// - table_kind 页表类型
    /// - table_paddr 根页表物理地址
    /// - allocator 页分配器
    ///
    /// ## 返回值
    ///
    /// 页面映射器
    pub unsafe fn new(table_kind: PageTableKind, table_paddr: PhysAddr, allocator: F) -> Self {
        return Self {
            table_kind,
            table_paddr,
            frame_allocator: allocator,
            phantom: PhantomData,
        };
    }

    /// 创建页表，并为这个页表创建页面映射器
    pub unsafe fn create(table_kind: PageTableKind, mut allocator: F) -> Option<Self> {
        let table_paddr = allocator.allocate_one()?;
        // 清空页表
        let table_vaddr = Arch::phys_2_virt(table_paddr)?;
        Arch::write_bytes(table_vaddr, 0, Arch::PAGE_SIZE);
        return Some(Self::new(table_kind, table_paddr, allocator));
    }

    /// 获取当前页表的页面映射器
    #[inline(always)]
    pub unsafe fn current(table_kind: PageTableKind, allocator: F) -> Self {
        let table_paddr = Arch::table(table_kind);
        return Self::new(table_kind, table_paddr, allocator);
    }

    /// 判断当前页表分配器所属的页表是否是当前页表
    #[inline(always)]
    pub fn is_current(&self) -> bool {
        return unsafe { self.table().phys() == Arch::table(self.table_kind) };
    }

    /// 将当前页表分配器所属的页表设置为当前页表
    #[inline(always)]
    pub unsafe fn make_current(&self) {
        Arch::set_table(self.table_kind, self.table_paddr);
    }

    /// 获取当前页表分配器所属的根页表的结构体
    #[inline(always)]
    pub fn table(&self) -> PageTable<Arch> {
        // 由于只能通过new方法创建PageMapper，因此这里假定table_paddr是有效的
        return unsafe {
            PageTable::new(VirtAddr::new(0), self.table_paddr, Arch::PAGE_LEVELS - 1)
        };
    }

    /// 获取当前PageMapper所对应的页分配器实例的引用
    #[inline(always)]
    #[allow(dead_code)]
    pub fn allocator_ref(&self) -> &F {
        return &self.frame_allocator;
    }

    /// 获取当前PageMapper所对应的页分配器实例的可变引用
    #[inline(always)]
    pub fn allocator_mut(&mut self) -> &mut F {
        return &mut self.frame_allocator;
    }

    /// 从当前PageMapper的页分配器中分配一个物理页，并将其映射到指定的虚拟地址
    pub unsafe fn map(
        &mut self,
        virt: VirtAddr,
        flags: EntryFlags<Arch>,
    ) -> Option<PageFlush<Arch>> {
        let mut page_manager_guard: SpinLockGuard<'static, PageManager> =
            page_manager_lock_irqsave();
        let page = page_manager_guard
            .create_one_page(
                PageType::Normal,
                PageFlags::empty(),
                &mut self.frame_allocator,
            )
            .ok()?;
        drop(page_manager_guard);
        let phys = page.phys_address();
        return self.map_phys(virt, phys, flags);
    }

    /// 映射一个物理页到指定的虚拟地址
    pub unsafe fn map_phys(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: EntryFlags<Arch>,
    ) -> Option<PageFlush<Arch>> {
        // 验证虚拟地址和物理地址是否对齐
        if !(virt.check_aligned(Arch::PAGE_SIZE) && phys.check_aligned(Arch::PAGE_SIZE)) {
            error!(
                "Try to map unaligned page: virt={:?}, phys={:?}",
                virt, phys
            );
            return None;
        }

        let virt = VirtAddr::new(virt.data() & (!Arch::PAGE_NEGATIVE_MASK));

        // TODO： 验证flags是否合法

        // 创建页表项
        let entry = PageEntry::new(phys, flags);
        let mut table = self.table();
        loop {
            let i = table.index_of(virt)?;

            assert!(i < Arch::PAGE_ENTRY_NUM);
            if table.level() == 0 {
                compiler_fence(Ordering::SeqCst);

                table.set_entry(i, entry);
                compiler_fence(Ordering::SeqCst);
                return Some(PageFlush::new(virt));
            } else {
                let next_table = table.next_level_table(i);
                if let Some(next_table) = next_table {
                    table = next_table;
                    // debug!("Mapping {:?} to next level table...", virt);
                } else {
                    // 分配下一级页表
                    let frame = self.frame_allocator.allocate_one()?;

                    // 清空这个页帧
                    MMArch::write_bytes(MMArch::phys_2_virt(frame).unwrap(), 0, MMArch::PAGE_SIZE);
                    // 设置页表项的flags
                    let flags: EntryFlags<Arch> =
                        EntryFlags::new_page_table(virt.kind() == PageTableKind::User);

                    // 把新分配的页表映射到当前页表
                    table.set_entry(i, PageEntry::new(frame, flags));

                    // 获取新分配的页表
                    table = table.next_level_table(i)?;
                }
            }
        }
    }

    /// 进行大页映射
    pub unsafe fn map_huge_page(
        &mut self,
        virt: VirtAddr,
        flags: EntryFlags<Arch>,
    ) -> Option<PageFlush<Arch>> {
        // 验证虚拟地址是否对齐
        if !(virt.check_aligned(Arch::PAGE_SIZE)) {
            error!("Try to map unaligned page: virt={:?}", virt);
            return None;
        }

        let virt = VirtAddr::new(virt.data() & (!Arch::PAGE_NEGATIVE_MASK));

        let mut table = self.table();
        loop {
            let i = table.index_of(virt)?;
            assert!(i < Arch::PAGE_ENTRY_NUM);
            let next_table = table.next_level_table(i);
            if let Some(next_table) = next_table {
                table = next_table;
            } else {
                break;
            }
        }

        // 支持2M、1G大页，即页表层级为1、2级的页表可以映射大页
        if table.level == 0 || table.level > 2 {
            return None;
        }

        let (phys, count) = self.frame_allocator.allocate(PageFrameCount::new(
            Arch::PAGE_ENTRY_NUM.pow(table.level as u32),
        ))?;

        MMArch::write_bytes(
            MMArch::phys_2_virt(phys).unwrap(),
            0,
            MMArch::PAGE_SIZE * count.data(),
        );

        table.set_entry(
            table.index_of(virt)?,
            PageEntry::new(phys, flags.set_huge_page(true)),
        )?;
        Some(PageFlush::new(virt))
    }

    /// 为虚拟地址分配指定层级的页表
    /// ## 参数
    ///
    /// - `virt`: 虚拟地址
    /// - `level`: 指定页表层级
    ///
    /// ## 返回值
    /// - Some(PageTable<Arch>): 虚拟地址对应层级的页表
    /// - None: 对应页表不存在
    pub unsafe fn allocate_table(
        &mut self,
        virt: VirtAddr,
        level: usize,
    ) -> Option<PageTable<Arch>> {
        let table = self.get_table(virt, level + 1)?;
        let i = table.index_of(virt)?;
        let frame = self.frame_allocator.allocate_one()?;

        // 清空这个页帧
        MMArch::write_bytes(MMArch::phys_2_virt(frame).unwrap(), 0, MMArch::PAGE_SIZE);

        // 设置页表项的flags
        let flags: EntryFlags<Arch> =
            EntryFlags::new_page_table(virt.kind() == PageTableKind::User);

        table.set_entry(i, PageEntry::new(frame, flags));
        table.next_level_table(i)
    }

    /// 获取虚拟地址的指定层级页表
    /// ## 参数
    ///
    /// - `virt`: 虚拟地址
    /// - `level`: 指定页表层级
    ///
    /// ## 返回值
    /// - Some(PageTable<Arch>): 虚拟地址对应层级的页表
    /// - None: 对应页表不存在
    pub fn get_table(&self, virt: VirtAddr, level: usize) -> Option<PageTable<Arch>> {
        let mut table = self.table();
        if level > Arch::PAGE_LEVELS - 1 {
            return None;
        }

        unsafe {
            loop {
                if table.level == level {
                    return Some(table);
                }
                let i = table.index_of(virt)?;
                assert!(i < Arch::PAGE_ENTRY_NUM);

                table = table.next_level_table(i)?;
            }
        }
    }

    /// 获取虚拟地址在指定层级页表的PageEntry
    /// ## 参数
    ///
    /// - `virt`: 虚拟地址
    /// - `level`: 指定页表层级
    ///
    /// ## 返回值
    /// - Some(PageEntry<Arch>): 虚拟地址在指定层级的页表的有效PageEntry
    /// - None: 无对应的有效PageEntry
    pub fn get_entry(&self, virt: VirtAddr, level: usize) -> Option<PageEntry<Arch>> {
        let table = self.get_table(virt, level)?;
        let i = table.index_of(virt)?;
        let entry = unsafe { table.entry(i) }?;

        if !entry.empty() {
            Some(entry)
        } else {
            None
        }

        // let mut table = self.table();
        // if level > Arch::PAGE_LEVELS - 1 {
        //     return None;
        // }
        // unsafe {
        //     loop {
        //         let i = table.index_of(virt)?;
        //         assert!(i < Arch::PAGE_ENTRY_NUM);

        //         if table.level == level {
        //             let entry = table.entry(i)?;
        //             if !entry.empty() {
        //                 return Some(entry);
        //             } else {
        //                 return None;
        //             }
        //         }

        //         table = table.next_level_table(i)?;
        //     }
        // }
    }

    /// 拷贝用户空间映射
    /// ## 参数
    ///
    /// - `umapper`: 要拷贝的用户空间
    /// - `copy_on_write`: 是否写时复制
    pub unsafe fn clone_user_mapping(&mut self, umapper: &mut Self, copy_on_write: bool) {
        let old_table = umapper.table();
        let new_table = self.table();
        let allocator = self.allocator_mut();
        // 顶级页表的[0, PAGE_KERNEL_INDEX)项为用户空间映射
        for entry_index in 0..Arch::PAGE_KERNEL_INDEX {
            if let Some(next_table) = old_table.next_level_table(entry_index) {
                let table = next_table.clone(allocator, copy_on_write).unwrap();
                let old_entry = old_table.entry(entry_index).unwrap();
                let entry = PageEntry::new(table.phys(), old_entry.flags());
                new_table.set_entry(entry_index, entry);
            }
        }
    }

    /// 将物理地址映射到具有线性偏移量的虚拟地址
    #[allow(dead_code)]
    pub unsafe fn map_linearly(
        &mut self,
        phys: PhysAddr,
        flags: EntryFlags<Arch>,
    ) -> Option<(VirtAddr, PageFlush<Arch>)> {
        let virt: VirtAddr = Arch::phys_2_virt(phys)?;
        return self.map_phys(virt, phys, flags).map(|flush| (virt, flush));
    }

    /// 修改虚拟地址的页表项的flags，并返回页表项刷新器
    ///
    /// 请注意，需要在修改完flags后，调用刷新器的flush方法，才能使修改生效
    ///
    /// ## 参数
    /// - virt 虚拟地址
    /// - flags 新的页表项的flags
    ///
    /// ## 返回值
    ///
    /// 如果修改成功，返回刷新器，否则返回None
    pub unsafe fn remap(
        &mut self,
        virt: VirtAddr,
        flags: EntryFlags<Arch>,
    ) -> Option<PageFlush<Arch>> {
        return self
            .visit(virt, |p1, i| {
                let mut entry = p1.entry(i)?;

                entry.set_flags(flags);
                p1.set_entry(i, entry);
                Some(PageFlush::new(virt))
            })
            .flatten();
    }

    /// 根据虚拟地址，查找页表，获取对应的物理地址和页表项的flags
    ///
    /// ## 参数
    ///
    /// - virt 虚拟地址
    ///
    /// ## 返回值
    ///
    /// 如果查找成功，返回物理地址和页表项的flags，否则返回None
    pub fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, EntryFlags<Arch>)> {
        let entry: PageEntry<Arch> = self.visit(virt, |p1, i| unsafe { p1.entry(i) })??;
        let paddr = entry.address().ok()?;
        let flags = entry.flags();
        return Some((paddr, flags));
    }

    /// 取消虚拟地址的映射，释放页面，并返回页表项刷新器
    ///
    /// 请注意，需要在取消映射后，调用刷新器的flush方法，才能使修改生效
    ///
    /// ## 参数
    ///
    /// - virt 虚拟地址
    /// - unmap_parents 是否在父页表内，取消空闲子页表的映射
    ///
    /// ## 返回值
    /// 如果取消成功，返回刷新器，否则返回None
    #[allow(dead_code)]
    pub unsafe fn unmap(&mut self, virt: VirtAddr, unmap_parents: bool) -> Option<PageFlush<Arch>> {
        let (paddr, _, flusher) = self.unmap_phys(virt, unmap_parents)?;
        self.frame_allocator.free_one(paddr);
        return Some(flusher);
    }

    /// 取消虚拟地址的映射，并返回物理地址和页表项的flags
    ///
    /// ## 参数
    ///
    /// - vaddr 虚拟地址
    /// - unmap_parents 是否在父页表内，取消空闲子页表的映射
    ///
    /// ## 返回值
    ///
    /// 如果取消成功，返回物理地址和页表项的flags，否则返回None
    pub unsafe fn unmap_phys(
        &mut self,
        virt: VirtAddr,
        unmap_parents: bool,
    ) -> Option<(PhysAddr, EntryFlags<Arch>, PageFlush<Arch>)> {
        if !virt.check_aligned(Arch::PAGE_SIZE) {
            error!("Try to unmap unaligned page: virt={:?}", virt);
            return None;
        }

        let table = self.table();
        return unmap_phys_inner(virt, &table, unmap_parents, self.allocator_mut())
            .map(|(paddr, flags)| (paddr, flags, PageFlush::<Arch>::new(virt)));
    }

    /// 在页表中，访问虚拟地址对应的页表项，并调用传入的函数F
    fn visit<T>(
        &self,
        virt: VirtAddr,
        f: impl FnOnce(&mut PageTable<Arch>, usize) -> T,
    ) -> Option<T> {
        let mut table = self.table();
        unsafe {
            loop {
                let i = table.index_of(virt)?;
                if table.level() == 0 {
                    return Some(f(&mut table, i));
                } else {
                    table = table.next_level_table(i)?;
                }
            }
        }
    }
}

/// 取消页面映射，返回被取消映射的页表项的：【物理地址】和【flags】
///
/// ## 参数
///
/// - vaddr 虚拟地址
/// - table 页表
/// - unmap_parents 是否在父页表内，取消空闲子页表的映射
/// - allocator 页面分配器（如果页表从这个分配器分配，那么在取消映射时，也需要归还到这个分配器内）
///
/// ## 返回值
///
/// 如果取消成功，返回被取消映射的页表项的：【物理地址】和【flags】，否则返回None
unsafe fn unmap_phys_inner<Arch: MemoryManagementArch>(
    vaddr: VirtAddr,
    table: &PageTable<Arch>,
    unmap_parents: bool,
    allocator: &mut impl FrameAllocator,
) -> Option<(PhysAddr, EntryFlags<Arch>)> {
    // 获取页表项的索引
    let i = table.index_of(vaddr)?;

    // 如果当前是最后一级页表，直接取消页面映射
    if table.level() == 0 {
        let entry = table.entry(i)?;
        table.set_entry(i, PageEntry::from_usize(0));
        return Some((entry.address().ok()?, entry.flags()));
    }

    let subtable = table.next_level_table(i)?;
    // 递归地取消映射
    let result = unmap_phys_inner(vaddr, &subtable, unmap_parents, allocator)?;

    // TODO: This is a bad idea for architectures where the kernel mappings are done in the process tables,
    // as these mappings may become out of sync
    if unmap_parents {
        // 如果子页表已经没有映射的页面了，就取消子页表的映射

        // 检查子页表中是否还有映射的页面
        let x = (0..Arch::PAGE_ENTRY_NUM)
            .map(|k| subtable.entry(k).expect("invalid page entry"))
            .any(|e| e.present());
        if !x {
            // 如果没有，就取消子页表的映射
            table.set_entry(i, PageEntry::from_usize(0));
            // 释放子页表
            allocator.free_one(subtable.phys());
        }
    }

    return Some(result);
}

impl<Arch, F: Debug> Debug for PageMapper<Arch, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageMapper")
            .field("table_paddr", &self.table_paddr)
            .field("frame_allocator", &self.frame_allocator)
            .finish()
    }
}

/// 页表刷新器的trait
pub trait Flusher<Arch: MemoryManagementArch> {
    /// 取消对指定的page flusher的刷新
    fn consume(&mut self, flush: PageFlush<Arch>);
}

/// 用于刷新某个虚拟地址的刷新器。这个刷新器一经产生，就必须调用flush()方法，
/// 否则会造成对页表的更改被忽略，这是不安全的
#[must_use = "The flusher must call the 'flush()', or the changes to page table will be unsafely ignored."]
pub struct PageFlush<Arch: MemoryManagementArch> {
    virt: VirtAddr,
    phantom: PhantomData<Arch>,
}

impl<Arch: MemoryManagementArch> PageFlush<Arch> {
    pub fn new(virt: VirtAddr) -> Self {
        return Self {
            virt,
            phantom: PhantomData,
        };
    }

    pub fn flush(self) {
        unsafe { Arch::invalidate_page(self.virt) };
    }

    /// 忽略掉这个刷新器
    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}

impl<Arch: MemoryManagementArch> Drop for PageFlush<Arch> {
    fn drop(&mut self) {
        unsafe {
            MMArch::invalidate_page(self.virt);
        }
    }
}

/// 用于刷新整个页表的刷新器。这个刷新器一经产生，就必须调用flush()方法，
/// 否则会造成对页表的更改被忽略，这是不安全的
#[must_use = "The flusher must call the 'flush()', or the changes to page table will be unsafely ignored."]
pub struct PageFlushAll<Arch: MemoryManagementArch> {
    phantom: PhantomData<fn() -> Arch>,
}

#[allow(dead_code)]
impl<Arch: MemoryManagementArch> PageFlushAll<Arch> {
    pub fn new() -> Self {
        return Self {
            phantom: PhantomData,
        };
    }

    pub fn flush(self) {
        unsafe { Arch::invalidate_all() };
    }

    /// 忽略掉这个刷新器
    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}

impl<Arch: MemoryManagementArch> Flusher<Arch> for PageFlushAll<Arch> {
    /// 为page flush all 实现consume，消除对单个页面的刷新。（刷新整个页表了就不需要刷新单个页面了）
    fn consume(&mut self, flush: PageFlush<Arch>) {
        unsafe { flush.ignore() };
    }
}

impl<Arch: MemoryManagementArch, T: Flusher<Arch> + ?Sized> Flusher<Arch> for &mut T {
    /// 允许一个flusher consume掉另一个flusher
    fn consume(&mut self, flush: PageFlush<Arch>) {
        <T as Flusher<Arch>>::consume(self, flush);
    }
}

impl<Arch: MemoryManagementArch> Flusher<Arch> for () {
    fn consume(&mut self, _flush: PageFlush<Arch>) {}
}

impl<Arch: MemoryManagementArch> Drop for PageFlushAll<Arch> {
    fn drop(&mut self) {
        unsafe {
            Arch::invalidate_all();
        }
    }
}

/// 未在当前CPU上激活的页表的刷新器
///
/// 如果页表没有在当前cpu上激活，那么需要发送ipi到其他核心，尝试在其他核心上刷新页表
///
/// TODO: 这个方式很暴力，也许把它改成在指定的核心上刷新页表会更好。（可以测试一下开销）
#[derive(Debug)]
pub struct InactiveFlusher;

impl InactiveFlusher {
    pub fn new() -> Self {
        return Self {};
    }
}

impl Flusher<MMArch> for InactiveFlusher {
    fn consume(&mut self, flush: PageFlush<MMArch>) {
        unsafe {
            flush.ignore();
        }
    }
}

impl Drop for InactiveFlusher {
    fn drop(&mut self) {
        // 发送刷新页表的IPI
        send_ipi(IpiKind::FlushTLB, IpiTarget::Other);
    }
}

/// # 把一个地址向下对齐到页大小
pub fn round_down_to_page_size(addr: usize) -> usize {
    addr & !(MMArch::PAGE_SIZE - 1)
}

/// # 把一个地址向上对齐到页大小
pub fn round_up_to_page_size(addr: usize) -> usize {
    round_down_to_page_size(addr + MMArch::PAGE_SIZE - 1)
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #6：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\perf\bpf.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use super::{PerfEventOps, Result};
use crate::arch::mm::LockedFrameAllocator;
use crate::arch::MMArch;
use crate::filesystem::page_cache::PageCache;
use crate::filesystem::vfs::{FilePrivateData, FileSystem, IndexNode};
use crate::include::bindings::linux_bpf::{
    perf_event_header, perf_event_mmap_page, perf_event_type,
};
use crate::libs::align::page_align_up;
use crate::libs::spinlock::{SpinLock, SpinLockGuard};
use crate::mm::allocator::page_frame::{PageFrameCount, PhysPageFrame};
use crate::mm::page::{page_manager_lock_irqsave, PageFlags, PageType};
use crate::mm::{MemoryManagementArch, PhysAddr};
use crate::perf::util::{LostSamples, PerfProbeArgs, PerfSample, SampleHeader};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Debug;
use system_error::SystemError;
const PAGE_SIZE: usize = MMArch::PAGE_SIZE;
#[derive(Debug)]
pub struct BpfPerfEvent {
    _args: PerfProbeArgs,
    data: SpinLock<BpfPerfEventData>,
}

#[derive(Debug)]
pub struct BpfPerfEventData {
    enabled: bool,
    mmap_page: RingPage,
    page_cache: Arc<PageCache>,
    offset: usize,
}

#[derive(Debug)]
pub struct RingPage {
    size: usize,
    ptr: usize,
    data_region_size: usize,
    lost: usize,
    phys_addr: PhysAddr,
}

impl RingPage {
    pub fn empty() -> Self {
        RingPage {
            ptr: 0,
            size: 0,
            data_region_size: 0,
            lost: 0,
            phys_addr: PhysAddr::new(0),
        }
    }

    pub fn new_init(start: usize, len: usize, phys_addr: PhysAddr) -> Self {
        Self::init(start as _, len, phys_addr)
    }

    fn init(ptr: *mut u8, size: usize, phys_addr: PhysAddr) -> Self {
        assert_eq!(size % PAGE_SIZE, 0);
        assert!(size / PAGE_SIZE >= 2);
        // The first page will be filled with perf_event_mmap_page
        unsafe {
            let perf_event_mmap_page = &mut *(ptr as *mut perf_event_mmap_page);
            perf_event_mmap_page.data_offset = PAGE_SIZE as u64;
            perf_event_mmap_page.data_size = (size - PAGE_SIZE) as u64;
            // user will read sample or lost record from data_tail
            perf_event_mmap_page.data_tail = 0;
            // kernel will write sample or lost record from data_head
            perf_event_mmap_page.data_head = 0;
            // It is a ring buffer.
        }
        RingPage {
            ptr: ptr as usize,
            size,
            data_region_size: size - PAGE_SIZE,
            lost: 0,
            phys_addr,
        }
    }

    #[inline]
    fn can_write(&self, data_size: usize, data_tail: usize, data_head: usize) -> bool {
        let capacity = self.data_region_size - data_head + data_tail;
        data_size <= capacity
    }

    pub fn write_event(&mut self, data: &[u8]) -> Result<()> {
        let data_tail = unsafe { &mut (*(self.ptr as *mut perf_event_mmap_page)).data_tail };
        let data_head = unsafe { &mut (*(self.ptr as *mut perf_event_mmap_page)).data_head };

        // user lib will update the tail after read the data,but it will not % data_region_size
        let perf_header_size = size_of::<perf_event_header>();
        let can_write_perf_header =
            self.can_write(perf_header_size, *data_tail as usize, *data_head as usize);

        if can_write_perf_header {
            let can_write_lost_record = self.can_write(
                size_of::<LostSamples>(),
                *data_tail as usize,
                *data_head as usize,
            );
            // if there is lost record, we need to write the lost record first
            if self.lost > 0 && can_write_lost_record {
                let new_data_head = self.write_lost(*data_head as usize)?;
                *data_head = new_data_head as u64;
                // log::info!(
                //     "Write lost record: {}, data_tail: {}, new_data_head: {}",
                //     self.lost,
                //     *data_tail,
                //     *data_head
                // );
                self.lost = 0;
                // try to write the event again
                return self.write_event(data);
            }
            let sample_size = PerfSample::calculate_size(data.len());
            let can_write_sample =
                self.can_write(sample_size, *data_tail as usize, *data_head as usize);
            // log::error!(
            //     "can_write_sample: {}, data_tail: {}, data_head: {}, data.len(): {}, region_size: {}",
            //     can_write_sample,
            //     *data_tail,
            //     *data_head,
            //     data.len(),
            //     self.data_region_size
            // );
            if can_write_sample {
                let new_data_head = self.write_sample(data, *data_head as usize)?;
                *data_head = new_data_head as u64;
                // log::info!(
                //     "Write sample record, data_tail: {}, new_data_head: {}",
                //     *data_tail,
                //     *data_head
                // );
            } else {
                self.lost += 1;
            }
        } else {
            self.lost += 1;
        }
        Ok(())
    }

    /// Write any data to the page.
    ///
    /// Return the new data_head
    fn write_any(&mut self, data: &[u8], data_head: usize) -> Result<()> {
        let data_region_len = self.data_region_size;
        let data_region = self.as_mut_slice()[PAGE_SIZE..].as_mut();
        let data_len = data.len();
        let start = data_head % data_region_len;
        let end = (data_head + data_len) % data_region_len;
        if start < end {
            data_region[start..end].copy_from_slice(data);
        } else {
            let first_len = data_region_len - start;
            data_region[start..start + first_len].copy_from_slice(&data[..first_len]);
            data_region[0..end].copy_from_slice(&data[first_len..]);
        }
        Ok(())
    }
    #[inline]
    fn fill_size(&self, data_head_mod: usize) -> usize {
        if self.data_region_size - data_head_mod < size_of::<perf_event_header>() {
            // The remaining space is not enough to write the perf_event_header
            // We need to fill the remaining space with 0
            self.data_region_size - data_head_mod
        } else {
            0
        }
    }

    /// Write a sample to the page.
    fn write_sample(&mut self, data: &[u8], data_head: usize) -> Result<usize> {
        let sample_size = PerfSample::calculate_size(data.len());
        let maybe_end = (data_head + sample_size) % self.data_region_size;
        let fill_size = self.fill_size(maybe_end);
        let perf_sample = PerfSample {
            s_hdr: SampleHeader {
                header: perf_event_header {
                    type_: perf_event_type::PERF_RECORD_SAMPLE as u32,
                    misc: 0,
                    size: size_of::<SampleHeader>() as u16 + data.len() as u16 + fill_size as u16,
                },
                size: data.len() as u32,
            },
            value: data,
        };
        self.write_any(perf_sample.s_hdr.as_bytes(), data_head)?;
        self.write_any(perf_sample.value, data_head + size_of::<SampleHeader>())?;
        Ok(data_head + sample_size + fill_size)
    }

    /// Write a lost record to the page.
    ///
    /// Return the new data_head
    fn write_lost(&mut self, data_head: usize) -> Result<usize> {
        let maybe_end = (data_head + size_of::<LostSamples>()) % self.data_region_size;
        let fill_size = self.fill_size(maybe_end);
        let lost = LostSamples {
            header: perf_event_header {
                type_: perf_event_type::PERF_RECORD_LOST as u32,
                misc: 0,
                size: size_of::<LostSamples>() as u16 + fill_size as u16,
            },
            id: 0,
            count: self.lost as u64,
        };
        self.write_any(lost.as_bytes(), data_head)?;
        Ok(data_head + size_of::<LostSamples>() + fill_size)
    }

    pub fn readable(&self) -> bool {
        let data_tail = unsafe { &(*(self.ptr as *mut perf_event_mmap_page)).data_tail };
        let data_head = unsafe { &(*(self.ptr as *mut perf_event_mmap_page)).data_head };
        data_tail != data_head
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
    }
}

impl BpfPerfEvent {
    pub fn new(args: PerfProbeArgs) -> Self {
        BpfPerfEvent {
            _args: args,
            data: SpinLock::new(BpfPerfEventData {
                enabled: false,
                mmap_page: RingPage::empty(),
                page_cache: PageCache::new(None),
                offset: 0,
            }),
        }
    }
    pub fn do_mmap(&self, _start: usize, len: usize, offset: usize) -> Result<()> {
        let mut data = self.data.lock();
        let mut page_manager_guard = page_manager_lock_irqsave();
        let (phy_addr, pages) = page_manager_guard.create_pages(
            PageType::Normal,
            PageFlags::PG_UNEVICTABLE,
            &mut LockedFrameAllocator,
            PageFrameCount::new(page_align_up(len) / PAGE_SIZE),
        )?;
        for i in 0..pages.len() {
            data.page_cache
                .lock_irqsave()
                .add_page(i, pages.get(i).unwrap());
        }
        let virt_addr = unsafe { MMArch::phys_2_virt(phy_addr) }.ok_or(SystemError::EFAULT)?;
        // create mmap page
        let mmap_page = RingPage::new_init(virt_addr.data(), len, phy_addr);
        data.mmap_page = mmap_page;
        data.offset = offset;
        Ok(())
    }

    pub fn write_event(&self, data: &[u8]) -> Result<()> {
        let mut inner_data = self.data.lock();
        inner_data.mmap_page.write_event(data)?;
        Ok(())
    }
}

impl Drop for BpfPerfEvent {
    fn drop(&mut self) {
        let mut page_manager_guard = page_manager_lock_irqsave();
        let data = self.data.lock();
        let phy_addr = data.mmap_page.phys_addr;
        let len = data.mmap_page.size;
        let page_count = PageFrameCount::new(len / PAGE_SIZE);
        let mut cur_phys = PhysPageFrame::new(phy_addr);
        for _ in 0..page_count.data() {
            page_manager_guard.remove_page(&cur_phys.phys_address());
            cur_phys = cur_phys.next();
        }
    }
}

impl IndexNode for BpfPerfEvent {
    fn mmap(&self, start: usize, len: usize, offset: usize) -> Result<()> {
        self.do_mmap(start, len, offset)
    }

    fn read_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &mut [u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("PerfEventInode does not support read")
    }

    fn write_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &[u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("PerfEventInode does not support write")
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        panic!("PerfEventInode does not have a filesystem")
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }
    fn list(&self) -> Result<Vec<String>> {
        Err(SystemError::ENOSYS)
    }

    fn page_cache(&self) -> Option<Arc<PageCache>> {
        Some(self.data.lock().page_cache.clone())
    }

    fn absolute_path(&self) -> core::result::Result<String, SystemError> {
        Ok(String::from("bpf_perf_event"))
    }
}

impl PerfEventOps for BpfPerfEvent {
    fn enable(&self) -> Result<()> {
        self.data.lock().enabled = true;
        Ok(())
    }
    fn disable(&self) -> Result<()> {
        self.data.lock().enabled = false;
        Ok(())
    }
    fn readable(&self) -> bool {
        self.data.lock().mmap_page.readable()
    }
}

pub fn perf_event_open_bpf(args: PerfProbeArgs) -> BpfPerfEvent {
    BpfPerfEvent::new(args)
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #7：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\perf\kprobe.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use super::Result;
use crate::arch::interrupt::TrapFrame;
use crate::arch::kprobe::KProbeContext;
use crate::bpf::helper::BPF_HELPER_FUN_SET;
use crate::bpf::prog::BpfProg;
use crate::debug::kprobe::args::KprobeInfo;
use crate::debug::kprobe::{register_kprobe, unregister_kprobe, LockKprobe};
use crate::filesystem::page_cache::PageCache;
use crate::filesystem::vfs::file::File;
use crate::filesystem::vfs::{FilePrivateData, FileSystem, IndexNode};
use crate::libs::casting::DowncastArc;
use crate::libs::spinlock::SpinLockGuard;
use crate::perf::util::PerfProbeArgs;
use crate::perf::{BasicPerfEbpfCallBack, PerfEventOps};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Debug;
use kprobe::{CallBackFunc, ProbeArgs};
use rbpf::EbpfVmRaw;
use system_error::SystemError;
#[derive(Debug)]
pub struct KprobePerfEvent {
    _args: PerfProbeArgs,
    kprobe: LockKprobe,
}

impl Drop for KprobePerfEvent {
    fn drop(&mut self) {
        unregister_kprobe(self.kprobe.clone());
    }
}

impl KprobePerfEvent {
    pub fn do_set_bpf_prog(&self, prog_file: Arc<File>) -> Result<()> {
        let file = prog_file
            .inode()
            .downcast_arc::<BpfProg>()
            .ok_or(SystemError::EINVAL)?;
        let prog_slice = file.insns();

        let prog_slice =
            unsafe { core::slice::from_raw_parts(prog_slice.as_ptr(), prog_slice.len()) };
        let mut vm = EbpfVmRaw::new(Some(prog_slice)).map_err(|e| {
            log::error!("create ebpf vm failed: {:?}", e);
            SystemError::EINVAL
        })?;

        for (id, f) in BPF_HELPER_FUN_SET.get() {
            vm.register_helper(*id, *f)
                .map_err(|_| SystemError::EINVAL)?;
        }

        // create a callback to execute the ebpf prog
        let callback;

        #[cfg(target_arch = "x86_64")]
        {
            use crate::perf::JITMem;

            log::info!("Using JIT compilation for BPF program on x86_64 architecture");
            let jit_mem = Box::new(JITMem::new());
            let jit_mem = Box::leak(jit_mem);
            let jit_mem_addr = core::ptr::from_ref::<JITMem>(jit_mem) as usize;
            vm.set_jit_exec_memory(jit_mem).unwrap();
            vm.jit_compile().unwrap();
            let basic_callback = BasicPerfEbpfCallBack::new(file, vm, jit_mem_addr);
            callback = Box::new(KprobePerfCallBack(basic_callback));
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            vm.register_allowed_memory(0..u64::MAX);
            let basic_callback = BasicPerfEbpfCallBack::new(file, vm);
            callback = Box::new(KprobePerfCallBack(basic_callback));
        }

        // update callback for kprobe
        self.kprobe.write().update_event_callback(callback);
        Ok(())
    }
}

pub struct KprobePerfCallBack(BasicPerfEbpfCallBack);

impl CallBackFunc for KprobePerfCallBack {
    fn call(&self, trap_frame: &dyn ProbeArgs) {
        let trap_frame = trap_frame.as_any().downcast_ref::<TrapFrame>().unwrap();
        let pt_regs = KProbeContext::from(trap_frame);
        let probe_context = unsafe {
            core::slice::from_raw_parts_mut(
                &pt_regs as *const KProbeContext as *mut u8,
                size_of::<KProbeContext>(),
            )
        };
        self.0.call(probe_context);
    }
}

impl IndexNode for KprobePerfEvent {
    fn read_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &mut [u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("read_at not implemented for PerfEvent");
    }

    fn write_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &[u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("write_at not implemented for PerfEvent");
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        panic!("fs not implemented for PerfEvent");
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(SystemError::ENOSYS)
    }

    fn page_cache(&self) -> Option<Arc<PageCache>> {
        None
    }

    fn absolute_path(&self) -> core::result::Result<String, SystemError> {
        Ok(String::from("kprobe_perf_event"))
    }
}

impl PerfEventOps for KprobePerfEvent {
    fn set_bpf_prog(&self, bpf_prog: Arc<File>) -> Result<()> {
        self.do_set_bpf_prog(bpf_prog)
    }
    fn enable(&self) -> Result<()> {
        self.kprobe.write().enable();
        Ok(())
    }
    fn disable(&self) -> Result<()> {
        self.kprobe.write().disable();
        Ok(())
    }

    fn readable(&self) -> bool {
        true
    }
}

pub fn perf_event_open_kprobe(args: PerfProbeArgs) -> KprobePerfEvent {
    let symbol = args.name.clone();
    log::info!("create kprobe for symbol: {symbol}");
    let kprobe_info = KprobeInfo {
        pre_handler: |_| {},
        post_handler: |_| {},
        fault_handler: None,
        event_callback: None,
        symbol: Some(symbol),
        addr: None,
        offset: 0,
        enable: false,
    };
    let kprobe = register_kprobe(kprobe_info).expect("create kprobe failed");
    KprobePerfEvent {
        _args: args,
        kprobe,
    }
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #8：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\perf\tracepoint.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use super::Result;
use crate::bpf::helper::BPF_HELPER_FUN_SET;
use crate::bpf::prog::BpfProg;
use crate::filesystem::page_cache::PageCache;
use crate::libs::casting::DowncastArc;
use crate::libs::spinlock::SpinLock;
use crate::perf::util::PerfProbeConfig;
use crate::perf::{BasicPerfEbpfCallBack, JITMem};
use crate::tracepoint::{TracePoint, TracePointCallBackFunc};
use crate::{
    filesystem::vfs::{file::File, FilePrivateData, FileSystem, IndexNode},
    libs::spinlock::SpinLockGuard,
    perf::{util::PerfProbeArgs, PerfEventOps},
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::{string::String, vec::Vec};
use core::any::Any;
use core::sync::atomic::AtomicUsize;
use rbpf::EbpfVmRaw;
use system_error::SystemError;

#[derive(Debug)]
pub struct TracepointPerfEvent {
    _args: PerfProbeArgs,
    tp: &'static TracePoint,
    ebpf_list: SpinLock<Vec<usize>>,
}

impl TracepointPerfEvent {
    pub fn new(args: PerfProbeArgs, tp: &'static TracePoint) -> TracepointPerfEvent {
        TracepointPerfEvent {
            _args: args,
            tp,
            ebpf_list: SpinLock::new(Vec::new()),
        }
    }
}

impl IndexNode for TracepointPerfEvent {
    fn read_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &mut [u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("read_at not implemented for TracepointPerfEvent");
    }

    fn write_at(
        &self,
        _offset: usize,
        _len: usize,
        _buf: &[u8],
        _data: SpinLockGuard<FilePrivateData>,
    ) -> Result<usize> {
        panic!("write_at not implemented for TracepointPerfEvent");
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        panic!("fs not implemented for TracepointPerfEvent");
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }

    fn list(&self) -> Result<Vec<String>> {
        Err(SystemError::ENOSYS)
    }

    fn page_cache(&self) -> Option<Arc<PageCache>> {
        None
    }

    fn absolute_path(&self) -> core::result::Result<String, SystemError> {
        Ok(format!(
            "tracepoint: {}:{}",
            self.tp.system(),
            self.tp.name()
        ))
    }
}

pub struct TracePointPerfCallBack(BasicPerfEbpfCallBack);

impl TracePointCallBackFunc for TracePointPerfCallBack {
    fn call(&self, entry: &[u8]) {
        // ebpf needs a mutable slice
        let entry =
            unsafe { core::slice::from_raw_parts_mut(entry.as_ptr() as *mut u8, entry.len()) };
        self.0.call(entry);
    }
}

impl PerfEventOps for TracepointPerfEvent {
    fn set_bpf_prog(&self, bpf_prog: Arc<File>) -> Result<()> {
        static CALLBACK_ID: AtomicUsize = AtomicUsize::new(0);

        let file = bpf_prog
            .inode()
            .downcast_arc::<BpfProg>()
            .ok_or(SystemError::EINVAL)?;
        let prog_slice = file.insns();

        let prog_slice =
            unsafe { core::slice::from_raw_parts(prog_slice.as_ptr(), prog_slice.len()) };
        let mut vm = EbpfVmRaw::new(Some(prog_slice)).map_err(|e| {
            log::error!("create ebpf vm failed: {:?}", e);
            SystemError::EINVAL
        })?;
        for (id, f) in BPF_HELPER_FUN_SET.get() {
            vm.register_helper(*id, *f)
                .map_err(|_| SystemError::EINVAL)?;
        }

        // create a callback to execute the ebpf prog
        let callback;

        #[cfg(target_arch = "x86_64")]
        {
            log::info!("Using JIT compilation for BPF program on x86_64 architecture");
            let jit_mem = Box::new(JITMem::new());
            let jit_mem = Box::leak(jit_mem);
            let jit_mem_addr = core::ptr::from_ref::<JITMem>(jit_mem) as usize;
            vm.set_jit_exec_memory(jit_mem).unwrap();
            vm.jit_compile().unwrap();
            let basic_callback = BasicPerfEbpfCallBack::new(file, vm, jit_mem_addr);
            callback = Box::new(TracePointPerfCallBack(basic_callback));
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            vm.register_allowed_memory(0..u64::MAX);
            let basic_callback = BasicPerfEbpfCallBack::new(file, vm);
            callback = Box::new(TracePointPerfCallBack(basic_callback));
        }

        let id = CALLBACK_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.tp.register_raw_callback(id, callback);

        log::info!(
            "Registered BPF program for tracepoint: {}:{} with ID: {}",
            self.tp.system(),
            self.tp.name(),
            id
        );
        // Store the ID in the ebpf_list for later cleanup
        self.ebpf_list.lock().push(id);
        Ok(())
    }

    fn enable(&self) -> Result<()> {
        log::info!(
            "Enabling tracepoint event: {}:{}",
            self.tp.system(),
            self.tp.name()
        );
        self.tp.enable();
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        self.tp.disable();
        Ok(())
    }

    fn readable(&self) -> bool {
        true
    }
}

impl Drop for TracepointPerfEvent {
    fn drop(&mut self) {
        // Unregister all callbacks associated with this tracepoint event
        let mut ebpf_list = self.ebpf_list.lock();
        for id in ebpf_list.iter() {
            self.tp.unregister_raw_callback(*id);
        }
        ebpf_list.clear();
    }
}

/// Creates a new `TracepointPerfEvent` for the given tracepoint ID.
pub fn perf_event_open_tracepoint(args: PerfProbeArgs) -> Result<TracepointPerfEvent> {
    let tp_id = match args.config {
        PerfProbeConfig::Raw(tp_id) => tp_id as u32,
        _ => {
            panic!("Invalid PerfProbeConfig for TracepointPerfEvent");
        }
    };
    let tp_manager = crate::debug::tracing::tracing_events_manager();
    let tp_map = tp_manager.tracepoint_map();
    let tp = tp_map.get(&tp_id).ok_or(SystemError::ENOENT)?;
    Ok(TracepointPerfEvent::new(args, tp))
}

```

**💡 建议：**
Ensure Drop implementations never panic

#### 漏洞 #9：Potential panic in Drop implementation detected

**详情：**
- **Type:** `drop-panic`
- **Severity:** `Critical`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\process\namespace\mnt.rs:0`
- **检测方法：** `StaticAnalysis`

**解释：**
Drop implementation may panic, which can cause undefined behavior

**代码：**
```rust
use crate::{
    filesystem::vfs::{
        mount::{MountFlags, MountList, MountPath},
        FileSystem, IndexNode, InodeId, MountFS,
    },
    libs::{once::Once, spinlock::SpinLock},
    process::{fork::CloneFlags, namespace::NamespaceType, ProcessManager},
};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use system_error::SystemError;

use super::{nsproxy::NsCommon, user_namespace::UserNamespace, NamespaceOps};

static mut INIT_MNT_NAMESPACE: Option<Arc<MntNamespace>> = None;

/// 初始化root mount namespace
pub fn mnt_namespace_init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        INIT_MNT_NAMESPACE = Some(MntNamespace::new_root());
    });
}

int_like!(MntSharedGroupId, usize);

/// 获取全局的根挂载namespace
pub fn root_mnt_namespace() -> Arc<MntNamespace> {
    unsafe {
        INIT_MNT_NAMESPACE
            .as_ref()
            .expect("Mount namespace not initialized")
            .clone()
    }
}

pub struct MntNamespace {
    ns_common: NsCommon,
    self_ref: Weak<MntNamespace>,
    _user_ns: Arc<UserNamespace>,
    root_mountfs: Arc<MountFS>,
    inner: SpinLock<InnerMntNamespace>,
}

pub struct InnerMntNamespace {
    _dead: bool,
    mount_list: Arc<MountList>,
}

impl NamespaceOps for MntNamespace {
    fn ns_common(&self) -> &NsCommon {
        &self.ns_common
    }
}

impl MntNamespace {
    fn new_root() -> Arc<Self> {
        let mount_list = MountList::new();

        let ramfs = crate::filesystem::ramfs::RamFS::new();
        let ramfs = MountFS::new(
            ramfs,
            None,
            MountPropagation::new_private(),
            None,
            MountFlags::empty(),
        );

        let result = Arc::new_cyclic(|self_ref| Self {
            ns_common: NsCommon::new(0, NamespaceType::Mount),
            self_ref: self_ref.clone(),
            _user_ns: super::user_namespace::INIT_USER_NAMESPACE.clone(),
            root_mountfs: ramfs.clone(),
            inner: SpinLock::new(InnerMntNamespace {
                mount_list,
                _dead: false,
            }),
        });

        ramfs.set_namespace(Arc::downgrade(&result));
        result
            .add_mount(None, Arc::new(MountPath::from("/")), ramfs)
            .expect("Failed to add root mount");

        return result;
    }

    /// 强制替换本MountNamespace的根挂载文件系统
    ///
    /// 本方法仅供dragonos初始化时使用
    pub unsafe fn force_change_root_mountfs(&self, new_root: Arc<MountFS>) {
        let inner_guard = self.inner.lock();
        let ptr = self as *const Self as *mut Self;
        let self_mut = (ptr).as_mut().unwrap();
        self_mut.root_mountfs = new_root.clone();
        let (path, _, _) = inner_guard.mount_list.get_mount_point("/").unwrap();

        inner_guard.mount_list.insert(None, path, new_root);

        // update mount list ino
    }

    fn copy_with_mountfs(&self, new_root: Arc<MountFS>, _user_ns: Arc<UserNamespace>) -> Arc<Self> {
        let mut ns_common = self.ns_common.clone();
        ns_common.level += 1;

        let result = Arc::new_cyclic(|self_ref| Self {
            ns_common,
            self_ref: self_ref.clone(),
            _user_ns,
            root_mountfs: new_root.clone(),
            inner: SpinLock::new(InnerMntNamespace {
                _dead: false,
                mount_list: MountList::new(),
            }),
        });

        new_root.set_namespace(Arc::downgrade(&result));
        result
            .add_mount(None, Arc::new(MountPath::from("/")), new_root)
            .expect("Failed to add root mount");

        result
    }

    /// Creates a copy of the mount namespace for process cloning.
    ///
    /// This function is called during process creation to determine whether to create
    /// a new mount namespace or share the existing one based on the clone flags.
    ///
    /// # Arguments
    /// * `clone_flags` - Flags that control namespace creation behavior
    /// * `user_ns` - The user namespace to associate with the new mount namespace
    ///
    /// # Returns
    /// * `Ok(Arc<MntNamespace>)` - The appropriate mount namespace for the new process
    /// * `Err(SystemError)` - If namespace creation fails
    ///
    /// # Behavior
    /// - If `CLONE_NEWNS` is not set, returns the current mount namespace
    /// - If `CLONE_NEWNS` is set, creates a new mount namespace (currently unimplemented)
    #[inline(never)]
    pub fn copy_mnt_ns(
        &self,
        clone_flags: &CloneFlags,
        user_ns: Arc<UserNamespace>,
    ) -> Result<Arc<MntNamespace>, SystemError> {
        if !clone_flags.contains(CloneFlags::CLONE_NEWNS) {
            // Return the current mount namespace if CLONE_NEWNS is not set
            return Ok(self.self_ref.upgrade().unwrap());
        }
        let inner = self.inner.lock();

        let old_root_mntfs = self.root_mntfs().clone();
        let mut queue: Vec<MountFSCopyInfo> = Vec::new();

        // 由于root mntfs比较特殊，因此单独复制。
        let new_root_mntfs = old_root_mntfs.deepcopy(None);
        let new_mntns = self.copy_with_mountfs(new_root_mntfs, user_ns);
        new_mntns
            .add_mount(
                None,
                Arc::new(MountPath::from("/")),
                new_mntns.root_mntfs().clone(),
            )
            .expect("Failed to add root mount");

        for x in inner.mount_list.clone_inner().values() {
            if Arc::ptr_eq(x, new_mntns.root_mntfs()) {
                continue; // Skip the root mountfs
            }
        }
        // 将root mntfs下的所有挂载点复制到新的mntns中
        for (ino, mfs) in old_root_mntfs.mountpoints().iter() {
            let mount_path = inner
                .mount_list
                .get_mount_path_by_ino(*ino)
                .ok_or_else(|| {
                    panic!(
                        "mount_path not found for inode {:?}, mfs name: {}",
                        ino,
                        mfs.name()
                    );
                })
                .unwrap();

            queue.push(MountFSCopyInfo {
                old_mount_fs: mfs.clone(),
                parent_mount_fs: new_mntns.root_mntfs().clone(),
                self_mp_inode_id: *ino,
                mount_path,
            });
        }

        // 处理队列中的挂载点
        while let Some(data) = queue.pop() {
            let old_self_mp = data.old_mount_fs.self_mountpoint().unwrap();
            let new_self_mp = old_self_mp.clone_with_new_mount_fs(data.parent_mount_fs.clone());
            let new_mount_fs = data.old_mount_fs.deepcopy(Some(new_self_mp));
            data.parent_mount_fs
                .add_mount(data.self_mp_inode_id, new_mount_fs.clone())
                .expect("Failed to add mount");
            new_mntns
                .add_mount(
                    Some(data.self_mp_inode_id),
                    data.mount_path.clone(),
                    new_mount_fs.clone(),
                )
                .expect("Failed to add mount to mount namespace");

            // 原有的挂载点的子挂载点加入队列中

            for (child_ino, child_mfs) in data.old_mount_fs.mountpoints().iter() {
                queue.push(MountFSCopyInfo {
                    old_mount_fs: child_mfs.clone(),
                    parent_mount_fs: new_mount_fs.clone(),
                    self_mp_inode_id: *child_ino,
                    mount_path: inner
                        .mount_list
                        .get_mount_path_by_ino(*child_ino)
                        .expect("mount_path not found"),
                });
            }
        }

        // todo: 注册到procfs

        // 返回新创建的mount namespace
        Ok(new_mntns)
    }

    pub fn root_mntfs(&self) -> &Arc<MountFS> {
        &self.root_mountfs
    }

    /// 获取该挂载命名空间的根inode
    pub fn root_inode(&self) -> Arc<dyn IndexNode> {
        self.root_mountfs.root_inode()
    }

    pub fn add_mount(
        &self,
        ino: Option<InodeId>,
        mount_path: Arc<MountPath>,
        mntfs: Arc<MountFS>,
    ) -> Result<(), SystemError> {
        self.inner.lock().mount_list.insert(ino, mount_path, mntfs);
        return Ok(());
    }

    pub fn mount_list(&self) -> Arc<MountList> {
        self.inner.lock().mount_list.clone()
    }

    pub fn remove_mount(&self, mount_path: &str) -> Option<Arc<MountFS>> {
        return self.inner.lock().mount_list.remove(mount_path);
    }

    pub fn get_mount_point(
        &self,
        mount_point: &str,
    ) -> Option<(Arc<MountPath>, String, Arc<MountFS>)> {
        self.inner.lock().mount_list.get_mount_point(mount_point)
    }
}

/// Manages mount propagation relationships and state for mount points.
///
/// This struct tracks how mount events (mount, unmount, remount) propagate between
/// mount points according to their propagation types. It maintains relationships
/// between shared mounts, slave mounts, and their propagation groups.
#[derive(Clone)]
pub struct MountPropagation {
    /// The type of propagation behavior for this mount
    pub prop_type: PropagationType,
    /// Group ID for shared mounts that can propagate events to each other
    pub shared_group_id: Option<MntSharedGroupId>,
    /// Reference to the master mount for slave mounts
    pub master: Option<Weak<MountFS>>,
    /// List of slave mounts that receive events from this mount
    pub slaves: Vec<Weak<MountFS>>,
    /// Peer group ID for complex propagation relationships
    pub peer_group_id: Option<MntSharedGroupId>,
    /// Counter to prevent infinite loops during event propagation
    pub propagation_count: u32,
}

/// Defines the propagation type for mount points, controlling how mount events are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationType {
    /// Mount events do not propagate to or from this mount
    Private,
    /// Mount events propagate bidirectionally with other mounts in the same peer group
    Shared,
    /// Mount events propagate from the master mount to this slave mount
    Slave,
    /// Mount cannot be bind mounted and events do not propagate
    Unbindable,
}

impl MountPropagation {
    pub fn new_private() -> Arc<Self> {
        Arc::new(Self {
            prop_type: PropagationType::Private,
            shared_group_id: None,
            master: None,
            slaves: Vec::new(),
            peer_group_id: None,
            propagation_count: 0,
        })
    }

    pub fn new_shared(group_id: MntSharedGroupId) -> Arc<Self> {
        Arc::new(Self {
            prop_type: PropagationType::Shared,
            shared_group_id: Some(group_id),
            master: None,
            slaves: Vec::new(),
            peer_group_id: Some(group_id),
            propagation_count: 0,
        })
    }

    pub fn new_slave(master: Weak<MountFS>) -> Arc<Self> {
        Arc::new(Self {
            prop_type: PropagationType::Slave,
            shared_group_id: None,
            master: Some(master),
            slaves: Vec::new(),
            peer_group_id: None,
            propagation_count: 0,
        })
    }

    pub fn new_unbindable() -> Arc<Self> {
        Arc::new(Self {
            prop_type: PropagationType::Unbindable,
            shared_group_id: None,
            master: None,
            slaves: Vec::new(),
            peer_group_id: None,
            propagation_count: 0,
        })
    }

    /// 添加一个从属挂载
    pub fn add_slave(&mut self, slave: Weak<MountFS>) {
        self.slaves.push(slave);
    }

    /// 移除一个从属挂载
    pub fn remove_slave(&mut self, slave: &Weak<MountFS>) {
        self.slaves.retain(|s| !Weak::ptr_eq(s, slave));
    }

    /// 清理无效的从属挂载引用
    pub fn cleanup_stale_slaves(&mut self) {
        self.slaves.retain(|s| s.upgrade().is_some());
    }

    /// 重置传播计数器
    pub fn reset_propagation_count(&mut self) {
        self.propagation_count = 0;
    }
}

impl ProcessManager {
    /// 获取当前进程的挂载namespace
    pub fn current_mntns() -> Arc<MntNamespace> {
        if Self::initialized() {
            ProcessManager::current_pcb().nsproxy.read().mnt_ns.clone()
        } else {
            root_mnt_namespace()
        }
    }
}

struct MountFSCopyInfo {
    old_mount_fs: Arc<MountFS>,
    parent_mount_fs: Arc<MountFS>,
    self_mp_inode_id: InodeId,
    mount_path: Arc<MountPath>,
}

// impl Drop for MntNamespace {
//     fn drop(&mut self) {
//         log::warn!("mntns (level: {}) dropped", self.ns_common.level);
//     }
// }

```

**💡 建议：**
Ensure Drop implementations never panic

### High（共 1 条）

#### 漏洞 #1：Uninitialized memory read detected

**详情：**
- **Type:** `uninitialized-read`
- **Severity:** `High`
- **Confidence:** `90.0%`
- **Location:** `d:\漏洞挖掘\detector\project\DragonOS-master\kernel\src\arch\x86_64\init\boot_params.rs:395`
- **检测方法：** `StaticAnalysis`

**解释：**
assume_init used on uninitialized value within unsafe block

**代码：**
```rust
        unsafe { core::mem::MaybeUninit::<ArchBootParams>::zeroed().assume_init() };

    pub fn set_alt_mem_k(&mut self, alt_mem_k: u32) {
        self.alt_mem_k = alt_mem_k;
    }

    pub fn set_scratch(&mut self, scratch: u32) {
        self.scratch = scratch;
    }

    pub fn add_e820_entry(&mut self, addr: u64, size: u64, mtype: u32) {
        let entry = BootE820Entry {
            addr,
            size,
            type_: mtype,
        };
        self.e820_entries += 1;
        self.e820_table[self.e820_entries as usize] = entry;
    }

    pub fn init_setupheader(&mut self) {
        // 不设置就为0
        // 下面的是根据同等 qemu 环境(日期为2025.10.15)在启动 Linux 的值
        // 应该改成自己内核在初始化的过程中获得的值(部分值是需要写死的, 但不应该全部写死)
        self.hdr.setup_sects = 0x40;
        self.hdr.root_flags = 0xfb07;
        self.hdr.syssize = 0x00000d00;
        self.hdr.ram_size = 0x1000;
        self.hdr.vid_mode = 0x09;
        self.hdr.jump = 0xaa55;
        self.hdr.header = 0x53726448;
        self.hdr.version = 0x020f;
        self.hdr.start_sys_seg = 0x1000;
        self.hdr.kernel_version = 0x42a0;
        self.hdr.type_of_loader = 0xb0;
        self.hdr.loadflags = 0x83;
        self.hdr.setup_move_size = 0x8000;
        self.hdr.code32_start = 0x10000000;
        self.hdr.ramdisk_image = 0x00100000;
        self.hdr.ramdisk_size = 0x1eee6000;
        self.hdr.bootsect_kludge = 0x010e9eb0;
        self.hdr.heap_end_ptr = 0xfe00;
        self.hdr.cmd_line_ptr = 0x20000;
        self.hdr.initrd_addr_max = 0x7fffffff;
        self.hdr.kernel_alignment = 0x00200000;
        self.hdr.relocatable_kernel = 0x1;
        self.hdr.min_alignment = 0x15;
        self.hdr.xloadflags = 0x007f;
        self.hdr.cmdline_size = 0x7ff;
    }

    pub fn convert_to_buf(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
```

**💡 建议：**
Initialize memory before reading or avoid assume_init on uninit

---

*由 VulnFusion 生成 - 高级漏洞检测工具*
*融合 Rudra 与 SafeDrop 技术*
