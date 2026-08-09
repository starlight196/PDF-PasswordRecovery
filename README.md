# PDF 密码恢复

面向 Windows 的本地 PDF 字典密码恢复工具。界面和计算核心均为 C# 编译程序，不依赖 Python；PDF 只解析一次，密码校验在内存中多线程执行。

## 功能

- 导入本地 PDF 和文本字典
- 自动识别 UTF-8、GB18030、UTF-16 字典编码
- 可配置工作线程及密码字节编码
- 实时显示尝试次数、速度、进度、耗时和当前候选词
- 支持暂停、继续和停止
- 验证 PDF Standard Security `R2-R4` 的用户密码和所有者密码

## 构建

在 Windows 上运行：

```bat
build.cmd
```

生成文件位于 `bin\PdfPasswordRecovery.exe`。项目使用系统自带的 .NET Framework 4.8 编译器，无需安装 Python 或第三方运行库。

运行自测：

```bat
test.cmd
```

## 使用

1. 运行 `bin\PdfPasswordRecovery.exe`，选择要恢复的加密 PDF。
2. 导入文本字典；每行作为一个候选密码，空行代表空密码。
3. 按需选择字典编码、密码字节编码、线程数和空白处理方式。
4. 点击“开始”；界面会实时显示实际校验次数、速度、活动耗时和进度。

## 支持范围

- 支持 PDF Standard Security Handler `R2-R4` 的用户密码和所有者密码。
- 支持经典 xref 及其增量更新；不支持 xref stream、object stream 或混合 xref。
- 不支持 PDF `R5/R6`、Office 文档或 ZIP/RAR 等压缩文件。
- 单个 PDF 最大 2 GB；解析时会将 PDF 读入内存。

## 使用边界

只处理你有权访问的本地 PDF。程序不连接网络，也不会上传 PDF、字典或恢复结果。
