using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PdfPasswordRecovery
{
    internal sealed class MainForm : Form
    {
        private static readonly Color Canvas = Color.FromArgb(244, 246, 248);
        private static readonly Color Ink = Color.FromArgb(31, 41, 48);
        private static readonly Color Muted = Color.FromArgb(102, 113, 121);
        private static readonly Color Line = Color.FromArgb(213, 220, 225);
        private static readonly Color Accent = Color.FromArgb(24, 121, 93);
        private static readonly Color AccentDark = Color.FromArgb(17, 91, 71);
        private static readonly Color Warning = Color.FromArgb(183, 112, 24);
        private static readonly Color Danger = Color.FromArgb(177, 55, 55);
        private static readonly Color DisabledBack = Color.FromArgb(226, 231, 234);
        private static readonly Color DisabledInk = Color.FromArgb(126, 136, 143);
        private static readonly Color DisabledLine = Color.FromArgb(196, 204, 209);
        private const string EmptyPasswordDisplay = "（空密码）";
        private static PasswordVaultStorageMode rememberedVaultMode = PasswordVaultStorageMode.Aes256;
        private static string rememberedVaultPath = PasswordVault.DefaultAes256StoragePath;

        private readonly TextBox pdfPathBox = CreatePathBox();
        private readonly TextBox dictionaryPathBox = CreatePathBox();
        private readonly Button choosePdfButton = CreateSecondaryButton("选择 PDF");
        private readonly Button chooseDictionaryButton = CreateSecondaryButton("导入字典");
        private readonly ComboBox dictionaryEncodingBox = CreateComboBox();
        private readonly ComboBox passwordEncodingBox = CreateComboBox();
        private readonly NumericUpDown threadCountBox = new NumericUpDown();
        private readonly CheckBox trimWhitespaceBox = CreateCheckBox("去除首尾空白");
        private readonly CheckBox skipEmptyBox = CreateCheckBox("跳过空行");
        private readonly Label pdfInfoLabel = CreateMutedLabel("尚未选择 PDF");
        private readonly Label dictionaryInfoLabel = CreateMutedLabel("尚未导入字典");
        private readonly Label statusLabel = new Label();
        private readonly Label attemptsValue = CreateMetricValue("0");
        private readonly Label rateValue = CreateMetricValue("0 /秒");
        private readonly Label elapsedValue = CreateMetricValue("00:00:00");
        private readonly Label progressValue = CreateMetricValue("0.0%");
        private readonly ProgressBar progressBar = new ProgressBar();
        private readonly Label activityLabel = CreateMutedLabel("等待任务");
        private readonly Button startButton = CreatePrimaryButton("开始");
        private readonly Button pauseButton = CreateSecondaryButton("暂停");
        private readonly Button stopButton = CreateDangerButton("停止");
        private readonly TextBox resultBox = new TextBox();
        private readonly CheckBox showPasswordBox = CreateCheckBox("显示密码");
        private readonly Button copyButton = CreateSecondaryButton("复制");
        private readonly Button saveButton = CreateSecondaryButton("保存结果");
        private readonly Button passwordManagerButton = CreateHeaderButton("密码管理");
        private readonly RichTextBox logBox = new RichTextBox();
        private readonly Timer uiTimer = new Timer();

        private readonly DictionaryAttack attack = new DictionaryAttack();
        private PdfSecurityInfo securityInfo;
        private DictionaryInfo dictionaryInfo;
        private int pdfLoadVersion;
        private int dictionaryLoadVersion;
        private bool closingAfterStop;
        private string recoveredPassword = String.Empty;
        private bool hasRecoveredPassword;

        public MainForm()
        {
            Text = "PDF 密码恢复";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(900, 720);
            ClientSize = new Size(1040, 720);
            BackColor = Canvas;
            ForeColor = Ink;
            Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            AutoScaleMode = AutoScaleMode.Dpi;
            AllowDrop = true;
            DoubleBuffered = true;
            LoadApplicationIcon();

            BuildLayout();
            ConfigureAccessibility();
            WireEvents();
            ConfigureDefaults();
            UpdateControls();
            TrySelectInitialPdf();
        }

        private void LoadApplicationIcon()
        {
            try
            {
                using (Stream iconStream = typeof(MainForm).Assembly.GetManifestResourceStream("PdfPasswordRecovery.AppIcon"))
                {
                    if (iconStream == null) return;
                    using (Icon embeddedIcon = new Icon(iconStream))
                        Icon = (Icon)embeddedIcon.Clone();
                }
            }
            catch
            {
                // The form remains usable if Windows cannot read the executable icon.
            }
        }

        private void BuildLayout()
        {
            Controls.Add(BuildBody());
            Controls.Add(BuildHeader());
        }

        private Control BuildHeader()
        {
            Panel header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 74,
                BackColor = Color.FromArgb(29, 38, 44),
                Padding = new Padding(24, 12, 24, 10)
            };

            Label title = new Label
            {
                Text = "PDF 密码恢复",
                AutoSize = true,
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 17F, FontStyle.Bold),
                Location = new Point(22, 12)
            };
            Label subtitle = new Label
            {
                Text = "本地字典校验  |  Standard Security R2-R4",
                AutoSize = true,
                ForeColor = Color.FromArgb(184, 196, 203),
                Font = new Font("Microsoft YaHei UI", 8.5F),
                Location = new Point(25, 45)
            };
            statusLabel.Text = "待导入字典";
            statusLabel.AutoSize = false;
            statusLabel.TextAlign = ContentAlignment.MiddleCenter;
            statusLabel.ForeColor = Color.White;
            statusLabel.BackColor = Warning;
            statusLabel.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold);
            statusLabel.Size = new Size(82, 30);
            statusLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            statusLabel.Location = new Point(ClientSize.Width - 108, 22);

            passwordManagerButton.Size = new Size(104, 30);
            passwordManagerButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            passwordManagerButton.Location = new Point(statusLabel.Left - passwordManagerButton.Width - 12, 22);

            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            header.Controls.Add(passwordManagerButton);
            header.Controls.Add(statusLabel);
            header.Resize += delegate
            {
                statusLabel.Left = header.ClientSize.Width - statusLabel.Width - 24;
                passwordManagerButton.Left = statusLabel.Left - passwordManagerButton.Width - 12;
            };
            return header;
        }

        private Control BuildBody()
        {
            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(22, 16, 22, 18),
                BackColor = Canvas,
                ColumnCount = 1,
                RowCount = 10
            };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 155));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 12));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 86));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            root.Controls.Add(CreateSectionTitle("任务配置"), 0, 0);
            root.Controls.Add(BuildConfigurationPanel(), 0, 1);
            root.Controls.Add(CreateSeparator(), 0, 2);
            root.Controls.Add(CreateSectionTitle("运行状态"), 0, 3);
            root.Controls.Add(BuildMetricsPanel(), 0, 4);
            root.Controls.Add(BuildProgressPanel(), 0, 5);
            root.Controls.Add(BuildActivityPanel(), 0, 6);
            root.Controls.Add(BuildCommandPanel(), 0, 7);
            root.Controls.Add(CreateSectionTitle("事件记录"), 0, 8);

            logBox.Dock = DockStyle.Fill;
            logBox.ReadOnly = true;
            logBox.BorderStyle = BorderStyle.FixedSingle;
            logBox.BackColor = Color.White;
            logBox.ForeColor = Ink;
            logBox.Font = new Font("Consolas", 9F);
            logBox.DetectUrls = false;
            logBox.WordWrap = false;
            root.Controls.Add(logBox, 0, 9);
            return root;
        }

        private Control BuildConfigurationPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Padding = new Padding(12, 8, 12, 7),
                ColumnCount = 3,
                RowCount = 4,
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 82));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 108));
            for (int i = 0; i < 4; i++) panel.RowStyles.Add(new RowStyle(SizeType.Percent, 25));

            panel.Controls.Add(CreateFieldLabel("PDF 文件"), 0, 0);
            panel.Controls.Add(pdfPathBox, 1, 0);
            panel.Controls.Add(choosePdfButton, 2, 0);
            panel.Controls.Add(CreateFieldLabel("加密信息"), 0, 1);
            panel.Controls.Add(pdfInfoLabel, 1, 1);
            panel.SetColumnSpan(pdfInfoLabel, 2);
            panel.Controls.Add(CreateFieldLabel("密码字典"), 0, 2);
            panel.Controls.Add(dictionaryPathBox, 1, 2);
            panel.Controls.Add(chooseDictionaryButton, 2, 2);
            panel.Controls.Add(CreateFieldLabel("运行选项"), 0, 3);
            panel.Controls.Add(BuildOptionsPanel(), 1, 3);
            panel.SetColumnSpan(panel.GetControlFromPosition(1, 3), 2);

            pdfPathBox.Dock = DockStyle.Fill;
            dictionaryPathBox.Dock = DockStyle.Fill;
            choosePdfButton.Dock = DockStyle.Fill;
            chooseDictionaryButton.Dock = DockStyle.Fill;
            pdfInfoLabel.Dock = DockStyle.Fill;
            pdfInfoLabel.TextAlign = ContentAlignment.MiddleLeft;
            return panel;
        }

        private Control BuildOptionsPanel()
        {
            FlowLayoutPanel options = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 2, 0, 0),
                Margin = new Padding(0),
                BackColor = Color.White
            };

            options.Controls.Add(CreateInlineLabel("字典"));
            dictionaryEncodingBox.Width = 105;
            options.Controls.Add(dictionaryEncodingBox);
            options.Controls.Add(CreateInlineLabel("密码字节"));
            passwordEncodingBox.Width = 92;
            options.Controls.Add(passwordEncodingBox);
            options.Controls.Add(CreateInlineLabel("线程"));
            threadCountBox.Width = 58;
            threadCountBox.Minimum = 1;
            threadCountBox.Maximum = Math.Max(1, Environment.ProcessorCount * 2);
            threadCountBox.TextAlign = HorizontalAlignment.Center;
            options.Controls.Add(threadCountBox);
            options.Controls.Add(trimWhitespaceBox);
            options.Controls.Add(skipEmptyBox);
            return options;
        }

        private Control BuildMetricsPanel()
        {
            TableLayoutPanel metrics = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 1,
                BackColor = Canvas,
                Margin = new Padding(0)
            };
            for (int i = 0; i < 4; i++) metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
            metrics.Controls.Add(CreateMetric("已尝试", attemptsValue, true), 0, 0);
            metrics.Controls.Add(CreateMetric("实时速度", rateValue, false), 1, 0);
            metrics.Controls.Add(CreateMetric("活动耗时", elapsedValue, false), 2, 0);
            metrics.Controls.Add(CreateMetric("字典进度", progressValue, false), 3, 0);
            return metrics;
        }

        private Control BuildProgressPanel()
        {
            Panel panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 5, 0, 5) };
            progressBar.Dock = DockStyle.Fill;
            progressBar.Minimum = 0;
            progressBar.Maximum = 1000;
            progressBar.Style = ProgressBarStyle.Continuous;
            panel.Controls.Add(progressBar);
            return panel;
        }

        private Control BuildActivityPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                BackColor = Canvas
            };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            activityLabel.Dock = DockStyle.Fill;
            activityLabel.TextAlign = ContentAlignment.MiddleLeft;
            activityLabel.AutoEllipsis = true;
            dictionaryInfoLabel.AutoSize = false;
            dictionaryInfoLabel.Dock = DockStyle.Fill;
            dictionaryInfoLabel.TextAlign = ContentAlignment.MiddleRight;
            dictionaryInfoLabel.AutoEllipsis = true;
            panel.Controls.Add(activityLabel, 0, 0);
            panel.Controls.Add(dictionaryInfoLabel, 1, 0);
            return panel;
        }

        private Control BuildCommandPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 8,
                RowCount = 1,
                Padding = new Padding(0, 7, 0, 7),
                BackColor = Canvas
            };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 18));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 102));

            startButton.Dock = DockStyle.Fill;
            pauseButton.Dock = DockStyle.Fill;
            stopButton.Dock = DockStyle.Fill;
            panel.Controls.Add(startButton, 0, 0);
            panel.Controls.Add(pauseButton, 1, 0);
            panel.Controls.Add(stopButton, 2, 0);

            resultBox.Dock = DockStyle.Fill;
            resultBox.ReadOnly = true;
            resultBox.UseSystemPasswordChar = true;
            resultBox.BackColor = Color.White;
            resultBox.BorderStyle = BorderStyle.FixedSingle;
            resultBox.Font = new Font("Consolas", 10F);
            resultBox.Margin = new Padding(0, 2, 8, 2);
            panel.Controls.Add(resultBox, 4, 0);
            showPasswordBox.Dock = DockStyle.Fill;
            panel.Controls.Add(showPasswordBox, 5, 0);
            copyButton.Dock = DockStyle.Fill;
            saveButton.Dock = DockStyle.Fill;
            panel.Controls.Add(copyButton, 6, 0);
            panel.Controls.Add(saveButton, 7, 0);
            return panel;
        }

        private static Control CreateMetric(string caption, Label value, bool accent)
        {
            Panel panel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Margin = new Padding(0, 0, 8, 0),
                Padding = new Padding(12, 8, 12, 6)
            };
            Label title = CreateMutedLabel(caption);
            title.Location = new Point(12, 8);
            title.AutoSize = true;
            value.Location = new Point(10, 29);
            value.ForeColor = accent ? AccentDark : Ink;
            value.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            value.Width = panel.Width - 20;
            panel.Controls.Add(title);
            panel.Controls.Add(value);
            panel.Resize += delegate { value.Width = panel.ClientSize.Width - 20; };
            return panel;
        }

        private void WireEvents()
        {
            choosePdfButton.Click += delegate { BrowsePdf(); };
            chooseDictionaryButton.Click += delegate { BrowseDictionary(); };
            dictionaryEncodingBox.SelectedIndexChanged += delegate
            {
                if (!String.IsNullOrWhiteSpace(dictionaryPathBox.Text)) LoadDictionary(dictionaryPathBox.Text);
            };
            startButton.Click += delegate { StartAttack(); };
            pauseButton.Click += delegate
            {
                attack.TogglePause();
                UpdateFromSnapshot(attack.GetSnapshot());
            };
            stopButton.Click += delegate
            {
                attack.Stop();
                statusLabel.Text = "正在停止";
                statusLabel.BackColor = Warning;
                UpdateControls();
            };
            showPasswordBox.CheckedChanged += delegate { UpdateResultDisplay(); };
            copyButton.Click += delegate { CopyRecoveredPassword(); };
            saveButton.Click += delegate { SaveResult(); };
            passwordManagerButton.Click += delegate { OpenPasswordManager(); };
            attack.Completed += delegate
            {
                if (!IsDisposed && IsHandleCreated)
                    BeginInvoke(new Action(AttackCompleted));
            };
            uiTimer.Interval = 250;
            uiTimer.Tick += delegate { UpdateFromSnapshot(attack.GetSnapshot()); };
            uiTimer.Start();
            DragEnter += OnDragEnter;
            DragDrop += OnDragDrop;
            FormClosing += OnFormClosing;
            Shown += delegate { chooseDictionaryButton.Focus(); };
        }

        private void ConfigureDefaults()
        {
            dictionaryEncodingBox.Items.AddRange(new object[] { "自动检测", "UTF-8", "GB18030", "UTF-16 LE", "UTF-16 BE" });
            dictionaryEncodingBox.SelectedIndex = 0;
            passwordEncodingBox.Items.AddRange(new object[] { "UTF-8", "GB18030", "Latin-1", "系统 ANSI" });
            passwordEncodingBox.SelectedIndex = 0;
            threadCountBox.Value = Math.Max(1, Math.Min(Environment.ProcessorCount, (int)threadCountBox.Maximum));
            trimWhitespaceBox.Checked = false;
            skipEmptyBox.Checked = false;
            AppendLog("程序已就绪；所有数据仅在本机处理。", Muted);
        }

        private void ConfigureAccessibility()
        {
            SetAccessibility(pdfPathBox, "已选择的 PDF 文件路径", AccessibleRole.Text);
            SetAccessibility(dictionaryPathBox, "已导入的密码字典路径", AccessibleRole.Text);
            SetAccessibility(choosePdfButton, "选择 PDF 文件", AccessibleRole.PushButton);
            SetAccessibility(chooseDictionaryButton, "导入密码字典", AccessibleRole.PushButton);
            SetAccessibility(dictionaryEncodingBox, "字典文件编码", AccessibleRole.ComboBox);
            SetAccessibility(passwordEncodingBox, "密码字节编码", AccessibleRole.ComboBox);
            SetAccessibility(threadCountBox, "工作线程数", AccessibleRole.SpinButton);
            SetAccessibility(trimWhitespaceBox, "去除候选密码首尾空白", AccessibleRole.CheckButton);
            SetAccessibility(skipEmptyBox, "跳过字典空行", AccessibleRole.CheckButton);
            SetAccessibility(startButton, "开始密码恢复", AccessibleRole.PushButton);
            SetAccessibility(pauseButton, "暂停或继续密码恢复", AccessibleRole.PushButton);
            SetAccessibility(stopButton, "停止密码恢复", AccessibleRole.PushButton);
            SetAccessibility(resultBox, "恢复结果密码", AccessibleRole.Text);
            resultBox.AccessibleDescription = "尚未恢复密码。";
            SetAccessibility(showPasswordBox, "显示恢复出的密码", AccessibleRole.CheckButton);
            SetAccessibility(copyButton, "复制恢复出的密码", AccessibleRole.PushButton);
            SetAccessibility(saveButton, "保存密码恢复结果", AccessibleRole.PushButton);
            SetAccessibility(passwordManagerButton, "打开密码管理", AccessibleRole.PushButton);
        }

        private void BrowsePdf()
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "选择加密 PDF";
                dialog.Filter = "PDF 文件 (*.pdf)|*.pdf|所有文件 (*.*)|*.*";
                dialog.CheckFileExists = true;
                if (dialog.ShowDialog(this) == DialogResult.OK) LoadPdf(dialog.FileName);
            }
        }

        private void BrowseDictionary()
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "导入密码字典";
                dialog.Filter = "字典文件 (*.txt;*.dic;*.lst)|*.txt;*.dic;*.lst|所有文件 (*.*)|*.*";
                dialog.CheckFileExists = true;
                if (dialog.ShowDialog(this) == DialogResult.OK) LoadDictionary(dialog.FileName);
            }
        }

        private void LoadPdf(string path)
        {
            if (attack.IsActive) return;
            int version = ++pdfLoadVersion;
            ClearRecoveredPassword();
            securityInfo = null;
            pdfPathBox.Text = path;
            pdfInfoLabel.Text = "正在解析加密信息...";
            UpdateControls();

            Task.Factory.StartNew(delegate { return PdfSecurity.Load(path); })
                .ContinueWith(delegate(Task<PdfSecurityInfo> task)
                {
                    if (version != pdfLoadVersion || IsDisposed) return;
                    if (task.IsFaulted)
                    {
                        Exception error = task.Exception.Flatten().InnerException;
                        pdfInfoLabel.Text = "不可用：" + error.Message;
                        AppendLog("PDF 解析失败：" + error.Message, Danger);
                    }
                    else
                    {
                        securityInfo = task.Result;
                        pdfInfoLabel.Text = securityInfo.DisplayName;
                        AppendLog("已载入 PDF：" + Path.GetFileName(path) + "  |  " + securityInfo.DisplayName, AccentDark);
                    }
                    UpdateControls();
                }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        private void LoadDictionary(string path)
        {
            if (attack.IsActive) return;
            int version = ++dictionaryLoadVersion;
            ClearRecoveredPassword();
            dictionaryInfo = null;
            dictionaryPathBox.Text = path;
            dictionaryInfoLabel.Text = "正在统计字典...";
            UpdateControls();
            string requestedEncoding = Convert.ToString(dictionaryEncodingBox.SelectedItem);

            Task.Factory.StartNew(delegate { return DictionaryInfo.Analyze(path, requestedEncoding); })
                .ContinueWith(delegate(Task<DictionaryInfo> task)
                {
                    if (version != dictionaryLoadVersion || IsDisposed) return;
                    if (task.IsFaulted)
                    {
                        Exception error = task.Exception.Flatten().InnerException;
                        dictionaryInfoLabel.Text = "字典不可用";
                        AppendLog("字典读取失败：" + error.Message, Danger);
                    }
                    else
                    {
                        dictionaryInfo = task.Result;
                        dictionaryInfoLabel.Text = FormatInteger(dictionaryInfo.CandidateCount) + " 行  |  " +
                            FormatBytes(dictionaryInfo.ByteLength) + "  |  " + dictionaryInfo.EncodingLabel;
                        AppendLog("字典已就绪：" + FormatInteger(dictionaryInfo.CandidateCount) + " 个候选词。", AccentDark);
                    }
                    UpdateControls();
                }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        private void StartAttack()
        {
            if (securityInfo == null || dictionaryInfo == null) return;
            Encoding passwordEncoding;
            try { passwordEncoding = GetPasswordEncoding(); }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "编码错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            ClearRecoveredPassword();
            progressBar.Value = 0;
            AppendLog("开始任务：" + threadCountBox.Value + " 个工作线程，密码字节编码 " + passwordEncoding.WebName + "。", Ink);
            attack.Start(securityInfo, dictionaryInfo, (int)threadCountBox.Value, passwordEncoding,
                trimWhitespaceBox.Checked, skipEmptyBox.Checked);
            UpdateFromSnapshot(attack.GetSnapshot());
            UpdateControls();
        }

        private Encoding GetPasswordEncoding()
        {
            string selected = Convert.ToString(passwordEncodingBox.SelectedItem);
            if (selected == "UTF-8") return new UTF8Encoding(false, true);
            if (selected == "GB18030") return Encoding.GetEncoding("GB18030", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
            if (selected == "Latin-1") return Encoding.GetEncoding(28591, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);
            return Encoding.Default;
        }

        private void AttackCompleted()
        {
            AttackSnapshot snapshot = attack.GetSnapshot();
            UpdateFromSnapshot(snapshot);

            if (snapshot.State == AttackState.Found)
            {
                SetRecoveredPassword(snapshot.FoundPassword);
                string kind = snapshot.Match == PasswordMatch.Owner ? "所有者密码" : "用户密码";
                AppendLog("已找到" + kind + "，共完成 " + FormatInteger(snapshot.Attempts) + " 次校验。", AccentDark);
                System.Media.SystemSounds.Asterisk.Play();
            }
            else if (snapshot.State == AttackState.Exhausted)
            {
                AppendLog("字典已全部测试，未找到匹配密码。", Warning);
            }
            else if (snapshot.State == AttackState.Stopped)
            {
                AppendLog("任务已停止。", Warning);
            }
            else if (snapshot.State == AttackState.Failed)
            {
                AppendLog("任务失败：" + snapshot.ErrorMessage, Danger);
                MessageBox.Show(this, snapshot.ErrorMessage, "任务失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            UpdateControls();
            if (closingAfterStop) BeginInvoke(new Action(Close));
        }

        private void UpdateFromSnapshot(AttackSnapshot snapshot)
        {
            attemptsValue.Text = FormatInteger(snapshot.Attempts);
            rateValue.Text = FormatRate(snapshot.CandidatesPerSecond) + " /秒";
            elapsedValue.Text = FormatElapsed(snapshot.Elapsed);
            double progress = snapshot.TotalCandidates <= 0 ? 0 :
                Math.Min(1.0, snapshot.Attempts / (double)snapshot.TotalCandidates);
            if (snapshot.State == AttackState.Exhausted) progress = 1.0;
            progressValue.Text = (progress * 100).ToString("0.0") + "%";
            progressBar.Value = Math.Max(0, Math.Min(1000, (int)(progress * 1000)));

            switch (snapshot.State)
            {
                case AttackState.Running:
                    statusLabel.Text = "运行中";
                    statusLabel.BackColor = Accent;
                    activityLabel.Text = snapshot.CurrentCandidate.Length == 0 ? "正在读取候选词..." :
                        "正在校验：" + MaskCandidate(snapshot.CurrentCandidate);
                    break;
                case AttackState.Paused:
                    statusLabel.Text = "已暂停";
                    statusLabel.BackColor = Warning;
                    activityLabel.Text = "任务已暂停";
                    break;
                case AttackState.Found:
                    statusLabel.Text = "已找到";
                    statusLabel.BackColor = Accent;
                    activityLabel.Text = snapshot.Match == PasswordMatch.Owner ? "匹配所有者密码" : "匹配用户密码";
                    break;
                case AttackState.Exhausted:
                    statusLabel.Text = "已完成";
                    statusLabel.BackColor = Color.FromArgb(76, 91, 101);
                    activityLabel.Text = "字典已全部测试";
                    break;
                case AttackState.Stopped:
                    statusLabel.Text = "已停止";
                    statusLabel.BackColor = Warning;
                    activityLabel.Text = "任务已停止";
                    break;
                case AttackState.Failed:
                    statusLabel.Text = "失败";
                    statusLabel.BackColor = Danger;
                    activityLabel.Text = snapshot.ErrorMessage ?? "任务失败";
                    break;
                default:
                    if (securityInfo == null)
                    {
                        statusLabel.Text = String.IsNullOrWhiteSpace(pdfPathBox.Text) ? "待选择 PDF" : "正在解析";
                        statusLabel.BackColor = Warning;
                    }
                    else if (dictionaryInfo == null)
                    {
                        statusLabel.Text = String.IsNullOrWhiteSpace(dictionaryPathBox.Text) ? "待导入字典" : "读取字典";
                        statusLabel.BackColor = Warning;
                    }
                    else
                    {
                        statusLabel.Text = "就绪";
                        statusLabel.BackColor = Accent;
                    }
                    activityLabel.Text = "等待任务";
                    break;
            }
            pauseButton.Text = snapshot.State == AttackState.Paused ? "继续" : "暂停";
        }

        private void UpdateControls()
        {
            bool active = attack.IsActive;
            bool ready = securityInfo != null && dictionaryInfo != null;
            choosePdfButton.Enabled = !active;
            chooseDictionaryButton.Enabled = !active;
            dictionaryEncodingBox.Enabled = !active;
            passwordEncodingBox.Enabled = !active;
            threadCountBox.Enabled = !active;
            trimWhitespaceBox.Enabled = !active;
            skipEmptyBox.Enabled = !active;
            startButton.Enabled = !active && ready;
            pauseButton.Enabled = active;
            stopButton.Enabled = active;
            copyButton.Enabled = hasRecoveredPassword;
            saveButton.Enabled = hasRecoveredPassword;
            showPasswordBox.Enabled = hasRecoveredPassword && recoveredPassword.Length > 0;
            passwordManagerButton.Enabled = !active;

            ApplyButtonAppearance(choosePdfButton, Color.White, Ink, Line);
            ApplyButtonAppearance(chooseDictionaryButton, Color.White, Ink, Line);
            ApplyButtonAppearance(startButton, Accent, Color.White, Accent);
            ApplyButtonAppearance(pauseButton, Color.White, Ink, Line);
            ApplyButtonAppearance(stopButton, Color.White, Danger, Color.FromArgb(222, 172, 172));
            ApplyButtonAppearance(copyButton, Color.White, Ink, Line);
            ApplyButtonAppearance(saveButton, Color.White, Ink, Line);
            ApplyHeaderButtonAppearance(passwordManagerButton);
        }

        private void OpenPasswordManager()
        {
            PasswordRecord currentResult = CreateCurrentPasswordRecord();
            try
            {
                using (PasswordVaultAccessForm accessForm = new PasswordVaultAccessForm(
                    rememberedVaultMode, rememberedVaultPath))
                {
                    if (Icon != null) accessForm.Icon = (Icon)Icon.Clone();
                    if (accessForm.ShowDialog(this) != DialogResult.OK) return;

                    rememberedVaultMode = accessForm.SelectedMode;
                    rememberedVaultPath = accessForm.SelectedPath;
                    List<PasswordRecord> initialRecords = accessForm.InitialRecords;
                    PasswordVault vault = accessForm.TakeVault();
                    if (vault == null) throw new InvalidOperationException("密码库未成功打开。");

                    using (vault)
                    using (PasswordManagerForm form = new PasswordManagerForm(
                        vault, currentResult, initialRecords))
                    {
                        if (Icon != null) form.Icon = (Icon)Icon.Clone();
                        form.ShowDialog(this);
                    }
                }
            }
            catch (Exception ex)
            {
                AppendLog("密码管理打开失败：" + ex.Message, Danger);
                MessageBox.Show(this, "无法打开密码管理。\r\n\r\n" + ex.Message,
                    "密码管理", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private PasswordRecord CreateCurrentPasswordRecord()
        {
            if (!hasRecoveredPassword) return null;

            AttackSnapshot snapshot = attack.GetSnapshot();
            int codePage;
            try { codePage = GetPasswordEncoding().CodePage; }
            catch { codePage = Encoding.UTF8.CodePage; }

            string filePath = securityInfo == null ? pdfPathBox.Text : securityInfo.FilePath;
            return new PasswordRecord
            {
                Id = Guid.Empty,
                FilePath = filePath,
                Password = recoveredPassword,
                Match = snapshot.Match,
                PasswordEncodingCodePage = codePage,
                Note = String.Empty,
                DocumentFingerprint = PasswordDocumentFingerprint.FromPath(filePath)
            };
        }

        private void SaveResult()
        {
            if (!hasRecoveredPassword) return;
            using (SaveFileDialog dialog = new SaveFileDialog())
            {
                dialog.Title = "保存恢复结果";
                dialog.Filter = "文本文件 (*.txt)|*.txt";
                dialog.FileName = Path.GetFileNameWithoutExtension(pdfPathBox.Text) + "_密码.txt";
                if (dialog.ShowDialog(this) != DialogResult.OK) return;

                AttackSnapshot snapshot = attack.GetSnapshot();
                StringBuilder text = new StringBuilder();
                text.AppendLine("PDF: " + pdfPathBox.Text);
                text.AppendLine("字典: " + dictionaryPathBox.Text);
                text.AppendLine("密码: " + (recoveredPassword.Length == 0 ? EmptyPasswordDisplay : recoveredPassword));
                text.AppendLine("类型: " + (snapshot.Match == PasswordMatch.Owner ? "所有者密码" : "用户密码"));
                text.AppendLine("尝试次数: " + snapshot.Attempts);
                text.AppendLine("活动耗时: " + FormatElapsed(snapshot.Elapsed));
                try
                {
                    File.WriteAllText(dialog.FileName, text.ToString(), new UTF8Encoding(true));
                    AppendLog("结果已保存：" + dialog.FileName, AccentDark);
                }
                catch (Exception ex)
                {
                    AppendLog("结果保存失败：" + ex.Message, Danger);
                    MessageBox.Show(this, "无法保存恢复结果。\r\n\r\n" + ex.Message,
                        "保存失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void CopyRecoveredPassword()
        {
            if (!hasRecoveredPassword) return;
            try
            {
                if (recoveredPassword.Length == 0)
                {
                    Clipboard.Clear();
                    AppendLog("恢复结果为空密码；已清空剪贴板。", AccentDark);
                }
                else
                {
                    Clipboard.SetText(recoveredPassword);
                    AppendLog("密码已复制到剪贴板。", AccentDark);
                }
            }
            catch (Exception ex)
            {
                AppendLog("剪贴板操作失败：" + ex.Message, Danger);
                MessageBox.Show(this, "无法访问剪贴板。\r\n\r\n" + ex.Message,
                    "复制失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ClearRecoveredPassword()
        {
            recoveredPassword = String.Empty;
            hasRecoveredPassword = false;
            showPasswordBox.Checked = false;
            resultBox.UseSystemPasswordChar = true;
            resultBox.Clear();
            resultBox.AccessibleDescription = "尚未恢复密码。";
        }

        private void SetRecoveredPassword(string password)
        {
            recoveredPassword = password ?? String.Empty;
            hasRecoveredPassword = true;
            showPasswordBox.Checked = false;
            UpdateResultDisplay();
            resultBox.AccessibleDescription = recoveredPassword.Length == 0 ?
                "已恢复密码，结果为空密码。" : "已恢复密码；内容默认隐藏。";
        }

        private void UpdateResultDisplay()
        {
            if (!hasRecoveredPassword)
            {
                resultBox.UseSystemPasswordChar = true;
                resultBox.Clear();
                return;
            }

            if (recoveredPassword.Length == 0)
            {
                resultBox.UseSystemPasswordChar = false;
                resultBox.Text = EmptyPasswordDisplay;
                return;
            }

            resultBox.UseSystemPasswordChar = !showPasswordBox.Checked;
            resultBox.Text = recoveredPassword;
        }

        private static void ApplyButtonAppearance(Button button, Color enabledBackColor,
            Color enabledForeColor, Color enabledBorderColor)
        {
            button.BackColor = button.Enabled ? enabledBackColor : DisabledBack;
            button.ForeColor = button.Enabled ? enabledForeColor : DisabledInk;
            button.FlatAppearance.BorderColor = button.Enabled ? enabledBorderColor : DisabledLine;
            button.Cursor = button.Enabled ? Cursors.Hand : Cursors.Default;
        }

        private static void ApplyHeaderButtonAppearance(Button button)
        {
            button.BackColor = button.Enabled ? Color.FromArgb(40, 55, 63) : Color.FromArgb(48, 59, 65);
            button.ForeColor = button.Enabled ? Color.White : Color.FromArgb(128, 141, 149);
            button.FlatAppearance.BorderColor = button.Enabled ? Color.FromArgb(104, 124, 134) : Color.FromArgb(67, 79, 86);
            button.Cursor = button.Enabled ? Cursors.Hand : Cursors.Default;
        }

        private static void SetAccessibility(Control control, string name, AccessibleRole role)
        {
            control.AccessibleName = name;
            control.AccessibleRole = role;
        }

        private void TrySelectInitialPdf()
        {
            string[] roots = new string[]
            {
                Environment.CurrentDirectory,
                Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)) == null ?
                    AppDomain.CurrentDomain.BaseDirectory :
                    Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)).FullName
            };
            for (int i = 0; i < roots.Length; i++)
            {
                try
                {
                    string[] files = Directory.GetFiles(roots[i], "*.pdf", SearchOption.TopDirectoryOnly);
                    if (files.Length > 0)
                    {
                        LoadPdf(files[0]);
                        return;
                    }
                }
                catch { }
            }
        }

        private void OnDragEnter(object sender, DragEventArgs e)
        {
            if (!attack.IsActive && e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }

        private void OnDragDrop(object sender, DragEventArgs e)
        {
            if (attack.IsActive) return;
            string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
            if (files == null) return;
            for (int i = 0; i < files.Length; i++)
            {
                if (String.Equals(Path.GetExtension(files[i]), ".pdf", StringComparison.OrdinalIgnoreCase))
                    LoadPdf(files[i]);
                else
                    LoadDictionary(files[i]);
            }
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (attack.IsActive)
            {
                e.Cancel = true;
                closingAfterStop = true;
                Enabled = false;
                attack.Stop();
                return;
            }
            attack.Dispose();
        }

        private void AppendLog(string message, Color color)
        {
            if (logBox.TextLength > 0) logBox.AppendText(Environment.NewLine);
            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = Muted;
            logBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  ");
            logBox.SelectionColor = color;
            logBox.AppendText(message);
            logBox.SelectionColor = Ink;
            logBox.ScrollToCaret();
        }

        private static string MaskCandidate(string value)
        {
            if (String.IsNullOrEmpty(value)) return "(空密码)";
            int visible = Math.Min(2, value.Length);
            return value.Substring(0, visible) + new string('*', Math.Min(10, Math.Max(3, value.Length - visible)));
        }

        private static string FormatInteger(long value)
        {
            return value.ToString("N0");
        }

        private static string FormatRate(double value)
        {
            if (value >= 1000000) return (value / 1000000).ToString("0.00") + "M";
            if (value >= 1000) return (value / 1000).ToString("0.0") + "K";
            return value.ToString("0");
        }

        private static string FormatBytes(long value)
        {
            if (value >= 1024L * 1024 * 1024) return (value / (1024d * 1024 * 1024)).ToString("0.00") + " GB";
            if (value >= 1024L * 1024) return (value / (1024d * 1024)).ToString("0.0") + " MB";
            if (value >= 1024L) return (value / 1024d).ToString("0.0") + " KB";
            return value + " B";
        }

        private static string FormatElapsed(TimeSpan elapsed)
        {
            int hours = (int)elapsed.TotalHours;
            return hours.ToString("00") + ":" + elapsed.Minutes.ToString("00") + ":" + elapsed.Seconds.ToString("00");
        }

        private static Label CreateSectionTitle(string text)
        {
            return new Label
            {
                Text = text,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Ink,
                Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold)
            };
        }

        private static Label CreateFieldLabel(string text)
        {
            return new Label
            {
                Text = text,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Muted,
                Margin = new Padding(0)
            };
        }

        private static Label CreateInlineLabel(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                ForeColor = Muted,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(6, 6, 2, 0)
            };
        }

        private static Label CreateMutedLabel(string text)
        {
            return new Label { Text = text, AutoSize = true, ForeColor = Muted };
        }

        private static Label CreateMetricValue(string text)
        {
            return new Label
            {
                Text = text,
                AutoSize = false,
                Height = 36,
                ForeColor = Ink,
                Font = new Font("Segoe UI", 17F, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft,
                AutoEllipsis = true
            };
        }

        private static TextBox CreatePathBox()
        {
            return new TextBox
            {
                ReadOnly = true,
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 5, 9, 5)
            };
        }

        private static ComboBox CreateComboBox()
        {
            return new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Standard,
                Height = 26,
                Margin = new Padding(0, 1, 5, 0)
            };
        }

        private static CheckBox CreateCheckBox(string text)
        {
            return new CheckBox
            {
                Text = text,
                AutoSize = true,
                ForeColor = Ink,
                Margin = new Padding(8, 4, 0, 0)
            };
        }

        private static Button CreatePrimaryButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Accent;
            button.ForeColor = Color.White;
            button.FlatAppearance.MouseOverBackColor = AccentDark;
            return button;
        }

        private static Button CreateHeaderButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Color.FromArgb(40, 55, 63);
            button.ForeColor = Color.White;
            button.FlatAppearance.BorderColor = Color.FromArgb(104, 124, 134);
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(50, 69, 78);
            return button;
        }

        private static Button CreateSecondaryButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Color.White;
            button.ForeColor = Ink;
            button.FlatAppearance.BorderColor = Line;
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(235, 240, 242);
            return button;
        }

        private static Button CreateDangerButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Color.White;
            button.ForeColor = Danger;
            button.FlatAppearance.BorderColor = Color.FromArgb(222, 172, 172);
            button.FlatAppearance.BorderSize = 1;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(250, 235, 235);
            return button;
        }

        private static Button CreateFlatButton(string text)
        {
            return new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Margin = new Padding(4),
                Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold),
                UseVisualStyleBackColor = false
            };
        }

        private static Control CreateSeparator()
        {
            Panel holder = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 5, 0, 6) };
            Panel line = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = Line };
            holder.Controls.Add(line);
            return holder;
        }
    }
}
