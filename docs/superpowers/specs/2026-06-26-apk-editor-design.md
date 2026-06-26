# APK 编辑器设计

## 目标

在 MobSF 里增加一套 APK 编辑流程。用户可以对某个已经上传并完成静态分析的 APK 进入“编辑状态”，在编辑状态里执行 Frida Gadget 注入和混淆操作，最后点击保存。

保存时按编辑状态决定行为：

- 如果编辑过程中没有任何操作，保存不重打包、不签名、不生成新 APK，只关闭编辑状态并删除临时工作目录。
- 如果编辑过程中发生了变化，保存会基于编辑后的工作目录执行重打包、zipalign、签名，并生成一个新的 APK 供用户下载。

保存生成的新 APK 只提供下载。系统不会自动把它导入 MobSF，也不会自动触发新的静态扫描。用户如果想分析新 APK，需要自己重新上传，这是另一块功能。

## 第一版范围

第一版支持：

- 每个源 APK 同一时间最多一个 active 编辑会话。
- 同一个源 APK 的多个用户、子用户、多个浏览器窗口共享同一个 active 编辑会话。
- Frida Gadget 注入。
- 可配置混淆：
  - smali、包名、类名、方法名混淆。
  - 资源和 assets 混淆。
  - 防分析混淆。
- 默认使用 debug keystore 签名。
- 高级选项支持用户自定义 keystore 签名。
- Web 页面、REST API、编辑日志。
- 保存成功后下载新 APK。
- 放弃当前编辑。

第一版不做：

- 自动重新扫描生成的新 APK。
- 自动把生成的新 APK 导入 MobSF。
- 完整回滚或撤销历史。
- 通用文件编辑器。
- AndroidManifest 可视化编辑。
- XAPK、APKS、AAB、IPA、源码 ZIP 编辑。

## 关键术语

`source_md5` 是源 APK 的 MD5，也就是 MobSF 现有扫描记录使用的 checksum。

现有源 APK 通常位于：

```text
uploads/<source_md5>/<source_md5>.apk
```

`session_id` 是一次编辑草稿的唯一编号，不是 APK 的 hash。它用于区分一次具体的编辑会话，内部使用即可，普通页面不需要突出展示。

示例目录：

```text
uploads/<source_md5>/apk_editor/<session_id>/workspace/
uploads/<source_md5>/apk_editor/<session_id>/build/
uploads/<source_md5>/apk_editor/<session_id>/output/
uploads/<source_md5>/apk_editor/<session_id>/logs/editor.log
```

目录含义：

- `workspace/`：apktool 解包后的编辑工作目录。Frida 注入和混淆都改这里。
- `build/`：保存时的中间构建目录，例如 unsigned.apk、aligned.apk。
- `output/`：保存成功后的最终 APK。
- `logs/editor.log`：这次编辑会话的完整日志。

## 编辑会话模型

同一个源 APK 同一时间只能有一个 active 编辑会话。

规则：

- 如果没有 active 会话，用户点击“编辑 APK”时创建新会话，并用 apktool 把源 APK 解包到 `workspace/`。
- 如果解包失败，这个会话不能进入可编辑状态。系统要记录失败原因，能安全清理的临时文件要清理，页面/API 返回明确的启动失败。
- 如果已经存在 active 会话，用户再次点击“编辑 APK”时直接进入这个现有会话，不创建新的工作目录。
- 同一个源 APK 的不同用户、子用户、浏览器窗口都会进入同一个 active 会话。
- 所有编辑操作都修改同一个 `workspace/`。
- 会话有一个 `dirty` 标记。刚创建时是 `false`，只要有操作实际修改了 `workspace/`，就变成 `true`。

会话状态必须持久化到数据库里，并以数据库记录作为真实状态来源。文件目录只是工作产物，不能只靠目录是否存在判断会话是否 active 或 saved。

会话状态：

- `active`：正在编辑，可以执行操作。
- `saving`：正在保存。
- `saved`：已生成新 APK。
- `save_failed`：保存失败，保留工作目录，允许重试。
- `closed_no_changes`：没有任何变化就保存了，临时目录已删除。
- `discarded`：用户放弃编辑，临时目录已删除。

保存和放弃操作要基于 `source_md5` 加锁，防止两个请求同时打包、同时删除或状态互相覆盖。

## 多用户和多浏览器行为

多个用户或多个浏览器窗口操作同一个源 APK 时，逻辑是共享编辑会话。

例如：

- 浏览器 A 进入编辑状态并注入 Frida Gadget。
- 浏览器 B 进入同一个 APK 的编辑状态并执行混淆。
- 最后任意一个浏览器点击保存。

保存结果应该同时包含 Frida Gadget 注入和混淆结果，因为它们修改的是同一个 `workspace/`。

后台仍然要校验每次操作传入的 `session_id` 是否是当前 active 会话，避免旧页面、旧请求误操作已经关闭或已经保存的会话。

## Frida Gadget 注入

Frida Gadget 注入是一个编辑操作，不是保存操作。

用户点击“注入 Frida Gadget”后，后台只修改当前 active 会话的 `workspace/`，并把会话标记为 `dirty=true`。这个阶段不生成 APK。

行为：

- 从 `workspace/lib/<abi>/` 识别 APK 已有 ABI。
- 如果 APK 没有 native `lib/` 目录，允许用户或 API 调用方选择 ABI，默认使用 `arm64-v8a`。
- 为每个选中的 ABI 下载或复用对应的 `libfrida-gadget.so`。
- 把 Gadget 放到：

  ```text
  workspace/lib/<abi>/libfrida-gadget.so
  ```

- 在同一个 ABI 目录下新增或更新 Gadget 配置文件。
- 在应用启动路径插入 `System.loadLibrary(...)` 调用。
- 优先插入 Application 类；如果没有合适的 Application 类，再回退到启动 Activity。
- 记录注入 ABI、注入状态、配置摘要到会话元数据和日志。

这个操作必须幂等：

- 重复点击不能重复插入多个 `System.loadLibrary(...)`。
- 如果已经注入，应该返回“已注入”或只更新配置。
- 不能重复写入冲突的元数据。

Frida 隐藏处理放到混淆的高级选项里。开启后可以把 gadget 文件名和加载名一起改掉，但这类处理失败风险更高，所以默认关闭。

## 混淆

混淆也是编辑操作，直接作用在当前 active 会话的 `workspace/` 上。第一版支持三类混淆，但默认策略是稳定优先，避免轻易破坏 APK 可安装和可运行。

默认稳定策略：

- 尽量只处理应用自身包名下的 smali。
- 跳过 Android framework 包。
- 跳过已知三方库包。
- 跳过 Manifest 入口组件。
- 跳过 Android 生命周期方法。
- 跳过明显依赖反射的类名、方法名、字符串。
- 方法名混淆优先只处理 private/internal 方法。
- Manifest 引用的类默认不改，除非 Manifest 和所有引用能一起安全更新。
- 生成 mapping 文件，方便排查和日志查看。

### 1. Smali 混淆

支持内容：

- 重命名选中的包、类、方法。
- 同步更新 smali 文件里的引用。
- 保留排除列表里的类和方法。
- 记录 mapping。

第一版要以稳定为主，不追求对所有类和方法做最大程度混淆。

### 2. 资源和 assets 混淆

支持内容：

- 默认只重命名低风险 assets 文件。
- 高级选项可以启用 `res/` 文件重命名，并同步更新 XML 引用。
- 默认跳过 launcher icon。
- 默认跳过 Manifest 直接引用的资源。
- 默认跳过可能通过固定字符串加载的资源。

资源混淆比 smali 混淆更容易破坏运行时行为，所以应该作为可配置选项，不作为默认强制行为。

### 3. 防分析混淆

支持内容：

- 插入无害的 smali 类或方法。
- 可选字符串简单编码，并添加运行时解码 helper。
- 默认跳过类名、资源 ID、Manifest 值、URL scheme、组件名等高风险字符串。
- 可选 Frida 隐藏模式，对 gadget 相关文件名和加载名做一致性改名。

每次混淆都要记录：

- 用户选择的混淆选项。
- 生成的 mapping 文件路径。
- 修改数量摘要。
- 跳过规则摘要。
- 错误或警告。

重复执行混淆时，要么使用已有 mapping 保持幂等，要么明确开始一次新的混淆 pass，不能把引用改坏。

## 保存、签名和下载

保存操作负责关闭当前 active 编辑会话。

### `dirty=false` 时保存

如果编辑过程中没有任何实际操作：

- 不重打包。
- 不签名。
- 不生成新 APK。
- 会话状态改为 `closed_no_changes`。
- 数据库里保留这条会话状态记录，便于审计和状态历史查看。
- 删除整个 session 目录：

  ```text
  uploads/<source_md5>/apk_editor/<session_id>/
  ```

### `dirty=true` 时保存

如果编辑过程中发生了变化：

1. 会话状态改为 `saving`。
2. 用 apktool 构建：

   ```text
   apktool b workspace -o build/unsigned.apk
   ```

3. 用 zipalign 对齐：

   ```text
   zipalign -p 4 build/unsigned.apk build/aligned.apk
   ```

4. 用 apksigner 签名。
5. 写出最终 APK：

   ```text
   uploads/<source_md5>/apk_editor/<session_id>/output/<source_md5>-edited.apk
   ```

6. 会话状态改为 `saved`。
7. 删除 `workspace/` 和 `build/`。
8. 保留 `output/` 和 `logs/`。

### 签名策略

签名支持两种方式：

- 默认：使用 MobSF 管理的 debug keystore。
- 高级：用户提供 keystore、alias、store password、key password。

安全要求：

- keystore 密码和 key 密码不能写入日志。
- 自定义 keystore 密码只用于当前保存动作，保存完成后不长期保存。
- API 响应和页面错误信息不能泄露敏感参数。

### 保存失败

保存失败时：

- 会话状态改为 `save_failed`。
- 保留 `workspace/`、`build/`、`logs/`。
- 页面和 API 返回安全的错误摘要。
- 用户可以重试保存。
- 用户也可以放弃编辑。

### 下载

下载规则：

- 只有 `saved` 状态才允许下载。
- 下载的是当前 session `output/` 里的最终 APK。
- 下载不会导入 MobSF。
- 下载不会触发扫描。
- 下载不会修改这个 APK。

### 放弃编辑

用户点击“放弃编辑”时：

- 删除整个 session 目录。
- 会话状态改为 `discarded`。
- 不生成 APK。

## Web 页面

在 Android APK 静态分析报告页增加一个“APK 编辑器”卡片。只对 APK 扫描显示，不对 so、jar、aar、zip 等类型显示。

页面状态：

- 没有 active 会话：
  - 显示“编辑 APK”。
- active 会话：
  - 显示当前状态。
  - 显示 Frida Gadget 注入控制。
  - 显示混淆控制。
  - 显示“保存”、“放弃编辑”、“查看日志”。
- save_failed：
  - 显示错误摘要。
  - 显示“重试保存”、“放弃编辑”、“查看日志”。
- saved：
  - 显示“下载编辑后的 APK”。
  - 允许重新开始一次新的编辑。

页面操作应该调用 REST API。这样页面行为和 API 行为保持一致，不做两套逻辑。

## REST API

第一版增加和页面等价的 REST API：

```text
POST /api/v1/apk_editor/start
POST /api/v1/apk_editor/frida_gadget
POST /api/v1/apk_editor/obfuscate
POST /api/v1/apk_editor/save
POST /api/v1/apk_editor/discard
GET  /api/v1/apk_editor/status
GET  /api/v1/apk_editor/logs
GET  /api/v1/apk_editor/download
```

通用参数：

- `hash`：必填，源 APK 的 MD5。
- `session_id`：start 之后的编辑操作需要传，除非接口明确支持自动解析当前 active 会话。

API 要求：

- 复用 MobSF 现有 API key 和权限体系。
- 编辑操作至少要求 scan 权限。
- 校验 `hash` 必须是已存在的 APK 扫描。
- 校验请求的 `session_id` 必须是当前 active 会话。
- saved、discarded、closed_no_changes 状态不能继续执行编辑操作。
- 返回结构化 JSON，包含状态、session state、操作摘要和安全错误信息。

下载接口：

- 保存成功后可以返回文件响应。
- 如果没有可下载产物，要返回明确的 JSON 或 HTTP 错误。

## 日志

APK 编辑器需要同时保留结构化状态和文件日志。

结构化状态用于页面和 API 查询，至少包含：

- 源 APK MD5。
- session ID。
- 当前状态。
- dirty 标记。
- 创建时间、更新时间、保存时间。
- 最后错误摘要。
- 输出 APK 路径。
- 操作元数据。

文件日志路径：

```text
uploads/<source_md5>/apk_editor/<session_id>/logs/editor.log
```

日志内容包括：

- 会话创建。
- apktool 解包阶段。
- Frida Gadget 注入摘要。
- 混淆选项和混淆摘要。
- 构建、对齐、签名阶段。
- 下载事件。
- 放弃编辑事件。
- 错误阶段、退出码、错误摘要。

日志必须脱敏：

- keystore 密码。
- key 密码。
- Authorization header。
- API key。

页面和 API 读取日志时只返回用户可见、安全的日志。完整内部 traceback 可以留在服务端日志里，但不能把敏感信息暴露给用户。

## 实现建议

可以复用的现有项目能力：

- `mobsf/StaticAnalyzer/views/android/apk.py`：Android APK 静态分析上下文。
- `mobsf/StaticAnalyzer/views/android/converter.py`：apktool 调用方式。
- `mobsf/DynamicAnalyzer/tools/apk_patcher.py`：Frida Gadget 下载、反编译、重编译的雏形，但要修复路径和版本假设。
- `mobsf/MobSF/views/home.py`：下载响应工具。
- `mobsf/MobSF/views/authorization.py`：权限校验工具。
- Docker 镜像和源码里已有的 apksigner、Android build-tools、apktool、Java runtime。

实现上不要把所有逻辑都堆到 Django view 里。建议拆成小的服务层：

- 会话状态管理。
- 文件系统工作目录管理。
- Frida Gadget 注入操作。
- 混淆操作。
- build、zipalign、签名操作。
- Web 页面 views。
- API views。

## 测试计划

单元测试：

- 启动编辑会话会创建 workspace。
- 同一个源 APK 再次启动会返回 active 会话。
- clean session 保存后状态变为 `closed_no_changes`，并删除 session 目录。
- dirty session 保存会调用 build/sign 阶段，并保留 output/logs。
- 放弃编辑会删除 session 目录。
- 非法 hash 和非 active session 会被拒绝。
- 日志会脱敏。

mock 命令的集成测试：

- Frida 注入重复执行是幂等的。
- 混淆会把会话标记为 dirty，并写入 mapping 元数据。
- 保存失败会保留 workspace，并允许重试。
- 保存成功后能查询下载信息。

Docker 或手工验证：

- 上传一个 APK。
- 打开静态分析报告页。
- 点击“编辑 APK”。
- 注入 Frida Gadget。
- 执行默认混淆。
- 使用 debug 签名保存。
- 下载编辑后的 APK。
- 确认系统没有自动重新扫描。
- 确认没有任何操作时保存会删除临时 session 目录。
