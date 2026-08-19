using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace PdfPasswordRecovery
{
    internal sealed class PasswordVaultAccessForm : Form
    {
        private static readonly Color Canvas = Color.FromArgb(244, 246, 248);
        private static readonly Color Ink = Color.FromArgb(31, 41, 48);
        private static readonly Color Muted = Color.FromArgb(102, 113, 121);
        private static readonly Color Line = Color.FromArgb(213, 220, 225);
        private static readonly Color Accent = Color.FromArgb(24, 121, 93);
        private static readonly Color AccentDark = Color.FromArgb(17, 91, 71);
        private static readonly Color Warning = Color.FromArgb(183, 112, 24);
        private static readonly Color DisabledBack = Color.FromArgb(226, 231, 234);
        private static readonly Color DisabledInk = Color.FromArgb(126, 136, 143);
        private static readonly Color DisabledLine = Color.FromArgb(196, 204, 209);

        private readonly RadioButton plaintextModeButton = CreateModeButton("明文 JSON");
        private readonly RadioButton aesModeButton = CreateModeButton("AES-256");
        private readonly TextBox pathBox = CreateTextBox();
        private readonly Button browseButton = CreateSecondaryButton("浏览");
        private readonly Label passwordLabel = CreateFieldLabel("解锁密码");
        private readonly TextBox passwordBox = CreateTextBox();
        private readonly CheckBox showPasswordBox = CreateCheckBox("显示密码");
        private readonly Label confirmPasswordLabel = CreateFieldLabel("确认密码");
        private readonly TextBox confirmPasswordBox = CreateTextBox();
        private readonly Label noticeLabel = new Label();
        private readonly Label statusLabel = new Label();
        private readonly Button continueButton = CreatePrimaryButton("继续");
        private readonly Button cancelButton = CreateSecondaryButton("取消");
        private readonly TableLayoutPanel bodyTable = new TableLayoutPanel();

        private PasswordVault openedVault;
        private List<PasswordRecord> initialRecords;
        private string plaintextPath;
        private string aesPath;
        private bool updatingUi;
        private bool opening;

        public PasswordVaultStorageMode SelectedMode { get; private set; }
        public string SelectedPath { get; private set; }
        public List<PasswordRecord> InitialRecords { get { return initialRecords; } }

        public PasswordVaultAccessForm(PasswordVaultStorageMode initialMode, string initialPath)
        {
            plaintextPath = PasswordVault.DefaultPlaintextStoragePath;
            aesPath = PasswordVault.DefaultAes256StoragePath;
            if (!String.IsNullOrWhiteSpace(initialPath))
            {
                if (initialMode == PasswordVaultStorageMode.PlaintextJson) plaintextPath = initialPath;
                else aesPath = initialPath;
            }

            Text = "打开密码库";
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(680, 470);
            MinimumSize = new Size(620, 450);
            BackColor = Canvas;
            ForeColor = Ink;
            Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            AutoScaleMode = AutoScaleMode.Dpi;
            ShowInTaskbar = false;
            MinimizeBox = false;
            MaximizeBox = false;
            DoubleBuffered = true;

            ConfigureControls();
            Controls.Add(BuildLayout());
            ConfigureAccessibility();
            WireEvents();
            SelectMode(initialMode == PasswordVaultStorageMode.PlaintextJson ?
                PasswordVaultStorageMode.PlaintextJson : PasswordVaultStorageMode.Aes256);
            AcceptButton = continueButton;
            CancelButton = cancelButton;
        }

        public PasswordVault TakeVault()
        {
            PasswordVault result = openedVault;
            openedVault = null;
            return result;
        }

        private void ConfigureControls()
        {
            pathBox.Dock = DockStyle.Fill;
            pathBox.Margin = new Padding(0, 4, 8, 4);
            browseButton.Dock = DockStyle.Fill;
            browseButton.Margin = new Padding(0, 3, 0, 3);

            passwordBox.Dock = DockStyle.Fill;
            passwordBox.Margin = new Padding(0, 4, 8, 4);
            passwordBox.UseSystemPasswordChar = true;
            confirmPasswordBox.Dock = DockStyle.Fill;
            confirmPasswordBox.Margin = new Padding(0, 4, 0, 4);
            confirmPasswordBox.UseSystemPasswordChar = true;
            showPasswordBox.Dock = DockStyle.Fill;
            showPasswordBox.Margin = new Padding(0, 7, 0, 0);

            noticeLabel.Dock = DockStyle.Fill;
            noticeLabel.ForeColor = Muted;
            noticeLabel.TextAlign = ContentAlignment.TopLeft;
            noticeLabel.Padding = new Padding(0, 8, 0, 0);
            noticeLabel.AutoEllipsis = true;

            statusLabel.Dock = DockStyle.Fill;
            statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            statusLabel.ForeColor = Muted;
            statusLabel.AutoEllipsis = true;

            continueButton.Size = new Size(112, 34);
            cancelButton.Size = new Size(92, 34);
        }

        private Control BuildLayout()
        {
            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = Canvas,
                Margin = new Padding(0)
            };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            root.Controls.Add(BuildHeader(), 0, 0);
            root.Controls.Add(BuildBody(), 0, 1);
            root.Controls.Add(BuildFooter(), 0, 2);
            return root;
        }

        private Control BuildHeader()
        {
            Panel header = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(29, 38, 44),
                Margin = new Padding(0)
            };
            Label title = new Label
            {
                Text = "打开密码库",
                AutoSize = true,
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 15F, FontStyle.Bold),
                Location = new Point(20, 8)
            };
            Label subtitle = new Label
            {
                Text = "选择本次使用的存储方式和文件",
                AutoSize = true,
                ForeColor = Color.FromArgb(184, 196, 203),
                Font = new Font("Microsoft YaHei UI", 8.5F),
                Location = new Point(23, 37)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            return header;
        }

        private Control BuildBody()
        {
            bodyTable.Dock = DockStyle.Fill;
            bodyTable.BackColor = Canvas;
            bodyTable.Padding = new Padding(22, 14, 22, 12);
            bodyTable.ColumnCount = 2;
            bodyTable.RowCount = 7;
            bodyTable.Margin = new Padding(0);
            bodyTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 104));
            bodyTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 12));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            bodyTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            Label modeLabel = CreateSectionLabel("存储方式");
            bodyTable.Controls.Add(modeLabel, 0, 0);
            bodyTable.SetColumnSpan(modeLabel, 2);
            bodyTable.Controls.Add(BuildModeSelector(), 0, 1);
            bodyTable.SetColumnSpan(bodyTable.GetControlFromPosition(0, 1), 2);
            bodyTable.Controls.Add(CreateFieldLabel("密码库文件"), 0, 3);
            bodyTable.Controls.Add(BuildPathRow(), 1, 3);
            bodyTable.Controls.Add(passwordLabel, 0, 4);
            bodyTable.Controls.Add(BuildPasswordRow(), 1, 4);
            bodyTable.Controls.Add(confirmPasswordLabel, 0, 5);
            bodyTable.Controls.Add(confirmPasswordBox, 1, 5);
            bodyTable.Controls.Add(noticeLabel, 0, 6);
            bodyTable.SetColumnSpan(noticeLabel, 2);
            return bodyTable;
        }

        private Control BuildModeSelector()
        {
            TableLayoutPanel selector = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            selector.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            selector.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            plaintextModeButton.Dock = DockStyle.Fill;
            aesModeButton.Dock = DockStyle.Fill;
            plaintextModeButton.Margin = new Padding(0, 2, 4, 2);
            aesModeButton.Margin = new Padding(4, 2, 0, 2);
            selector.Controls.Add(plaintextModeButton, 0, 0);
            selector.Controls.Add(aesModeButton, 1, 0);
            return selector;
        }

        private Control BuildPathRow()
        {
            TableLayoutPanel row = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 78));
            row.Controls.Add(pathBox, 0, 0);
            row.Controls.Add(browseButton, 1, 0);
            return row;
        }

        private Control BuildPasswordRow()
        {
            TableLayoutPanel row = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            row.Controls.Add(passwordBox, 0, 0);
            row.Controls.Add(showPasswordBox, 1, 0);
            return row;
        }

        private Control BuildFooter()
        {
            TableLayoutPanel footer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Padding = new Padding(18, 10, 18, 10),
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.Controls.Add(statusLabel, 0, 0);

            FlowLayoutPanel actions = new FlowLayoutPanel
            {
                AutoSize = true,
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false,
                Margin = new Padding(0)
            };
            continueButton.Margin = new Padding(6, 0, 0, 0);
            cancelButton.Margin = new Padding(6, 0, 0, 0);
            actions.Controls.Add(continueButton);
            actions.Controls.Add(cancelButton);
            footer.Controls.Add(actions, 1, 0);
            return footer;
        }

        private void ConfigureAccessibility()
        {
            SetAccessibility(plaintextModeButton, "使用明文 JSON 密码库", AccessibleRole.RadioButton);
            SetAccessibility(aesModeButton, "使用 AES-256 加密密码库", AccessibleRole.RadioButton);
            SetAccessibility(pathBox, "密码库文件路径", AccessibleRole.Text);
            SetAccessibility(browseButton, "浏览密码库文件", AccessibleRole.PushButton);
            SetAccessibility(passwordBox, "AES 密码库密码", AccessibleRole.Text);
            SetAccessibility(confirmPasswordBox, "确认 AES 密码库创建密码", AccessibleRole.Text);
            SetAccessibility(showPasswordBox, "显示或隐藏密码库密码", AccessibleRole.CheckButton);
            SetAccessibility(continueButton, "打开或创建密码库", AccessibleRole.PushButton);
            SetAccessibility(cancelButton, "取消打开密码库", AccessibleRole.PushButton);
        }

        private void WireEvents()
        {
            plaintextModeButton.CheckedChanged += delegate
            {
                if (plaintextModeButton.Checked && !updatingUi)
                    ChangeMode(PasswordVaultStorageMode.PlaintextJson);
            };
            aesModeButton.CheckedChanged += delegate
            {
                if (aesModeButton.Checked && !updatingUi)
                    ChangeMode(PasswordVaultStorageMode.Aes256);
            };
            pathBox.TextChanged += delegate
            {
                if (updatingUi) return;
                if (CurrentMode() == PasswordVaultStorageMode.PlaintextJson) plaintextPath = pathBox.Text;
                else aesPath = pathBox.Text;
                ClearPasswords();
                UpdateModeState();
            };
            browseButton.Click += delegate { BrowseVault(); };
            showPasswordBox.CheckedChanged += delegate
            {
                passwordBox.UseSystemPasswordChar = !showPasswordBox.Checked;
                confirmPasswordBox.UseSystemPasswordChar = !showPasswordBox.Checked;
            };
            continueButton.Click += delegate { OpenVault(); };
            FormClosing += delegate { ClearPasswords(); };
            Shown += delegate { FocusInitialControl(); };
        }

        private void SelectMode(PasswordVaultStorageMode mode)
        {
            updatingUi = true;
            plaintextModeButton.Checked = mode == PasswordVaultStorageMode.PlaintextJson;
            aesModeButton.Checked = mode == PasswordVaultStorageMode.Aes256;
            pathBox.Text = mode == PasswordVaultStorageMode.PlaintextJson ? plaintextPath : aesPath;
            ApplyModeButtonAppearance(plaintextModeButton, plaintextModeButton.Checked);
            ApplyModeButtonAppearance(aesModeButton, aesModeButton.Checked);
            updatingUi = false;
            UpdateModeState();
        }

        private void ChangeMode(PasswordVaultStorageMode mode)
        {
            ClearPasswords();
            SelectMode(mode);
        }

        private PasswordVaultStorageMode CurrentMode()
        {
            return plaintextModeButton.Checked ? PasswordVaultStorageMode.PlaintextJson :
                PasswordVaultStorageMode.Aes256;
        }

        private void UpdateModeState()
        {
            PasswordVaultStorageMode mode = CurrentMode();
            string path = pathBox.Text.Trim();
            bool exists = false;
            try { exists = File.Exists(path); }
            catch { }
            bool aes = mode == PasswordVaultStorageMode.Aes256;

            bodyTable.RowStyles[4].Height = aes ? 40 : 0;
            bodyTable.RowStyles[5].Height = aes && !exists ? 40 : 0;
            passwordLabel.Visible = aes;
            passwordBox.Visible = aes;
            showPasswordBox.Visible = aes;
            confirmPasswordLabel.Visible = aes && !exists;
            confirmPasswordBox.Visible = aes && !exists;
            passwordLabel.Text = exists ? "解锁密码" : "创建密码";

            if (!aes)
            {
                noticeLabel.Text = "警告：明文 JSON 会将保存的 PDF 密码直接写入文件，任何能读取该文件的人都能看到密码。";
                noticeLabel.ForeColor = Warning;
                continueButton.Text = "继续";
            }
            else if (exists)
            {
                noticeLabel.Text = "现有 AES-256 密码库。请输入密码解锁。";
                noticeLabel.ForeColor = Muted;
                continueButton.Text = "解锁并打开";
            }
            else
            {
                noticeLabel.Text = "将创建新的 AES-256 密码库。创建密码至少 8 个字符，可使用中文。";
                noticeLabel.ForeColor = Muted;
                continueButton.Text = "创建并打开";
            }
            statusLabel.Text = exists ? "已选择现有文件" : "文件将在首次保存条目时创建";
        }

        private void BrowseVault()
        {
            PasswordVaultStorageMode mode = CurrentMode();
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "选择密码库文件";
                dialog.Filter = mode == PasswordVaultStorageMode.PlaintextJson ?
                    "JSON 密码库 (*.json)|*.json|所有文件 (*.*)|*.*" :
                    "AES-256 密码库 (*.aesvault)|*.aesvault|所有文件 (*.*)|*.*";
                dialog.CheckFileExists = false;
                dialog.CheckPathExists = true;
                dialog.AddExtension = true;
                dialog.DefaultExt = mode == PasswordVaultStorageMode.PlaintextJson ? "json" : "aesvault";
                if (!String.IsNullOrWhiteSpace(pathBox.Text)) dialog.FileName = pathBox.Text;
                if (dialog.ShowDialog(this) == DialogResult.OK) pathBox.Text = dialog.FileName;
            }
        }

        private void OpenVault()
        {
            if (opening) return;
            string fullPath;
            try
            {
                if (String.IsNullOrWhiteSpace(pathBox.Text))
                    throw new ArgumentException("密码库文件路径不能为空。");
                fullPath = Path.GetFullPath(pathBox.Text.Trim());
            }
            catch (Exception ex)
            {
                ShowValidation(ex.Message, pathBox);
                return;
            }

            PasswordVaultStorageMode mode = CurrentMode();
            bool exists = File.Exists(fullPath);
            string password = passwordBox.Text;
            if (mode == PasswordVaultStorageMode.Aes256)
            {
                if (password.Length == 0)
                {
                    ShowValidation(exists ? "请输入解锁密码。" : "请输入创建密码。", passwordBox);
                    return;
                }
                if (!exists && password.Length < 8)
                {
                    ShowValidation("创建密码至少需要 8 个字符。", passwordBox);
                    return;
                }
                if (!exists && !String.Equals(password, confirmPasswordBox.Text, StringComparison.Ordinal))
                {
                    ShowValidation("两次输入的创建密码不一致。", confirmPasswordBox);
                    return;
                }
            }

            PasswordVault candidate = null;
            SetOpeningState(true, "正在打开密码库...");
            try
            {
                candidate = mode == PasswordVaultStorageMode.PlaintextJson ?
                    PasswordVault.OpenPlaintext(fullPath) : PasswordVault.OpenAes256(fullPath, password);
                List<PasswordRecord> snapshot = candidate.Load();
                openedVault = candidate;
                candidate = null;
                initialRecords = snapshot ?? new List<PasswordRecord>();
                SelectedMode = mode;
                SelectedPath = fullPath;
                password = String.Empty;
                ClearPasswords();
                DialogResult = DialogResult.OK;
                Close();
            }
            catch (Exception ex)
            {
                if (candidate != null) candidate.Dispose();
                password = String.Empty;
                ClearPasswords();
                SetOpeningState(false, "打开失败");
                MessageBox.Show(this, "无法打开密码库。\r\n\r\n" + ex.Message,
                    "密码库", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (mode == PasswordVaultStorageMode.Aes256) passwordBox.Focus();
                else pathBox.Focus();
            }
        }

        private void SetOpeningState(bool value, string status)
        {
            opening = value;
            plaintextModeButton.Enabled = !value;
            aesModeButton.Enabled = !value;
            pathBox.Enabled = !value;
            browseButton.Enabled = !value;
            passwordBox.Enabled = !value;
            confirmPasswordBox.Enabled = !value;
            showPasswordBox.Enabled = !value;
            continueButton.Enabled = !value;
            cancelButton.Enabled = !value;
            statusLabel.Text = status;
            UseWaitCursor = value;
            ApplyButtonAppearance(browseButton, Color.White, Ink, Line);
            ApplyButtonAppearance(continueButton, Accent, Color.White, Accent);
            ApplyButtonAppearance(cancelButton, Color.White, Ink, Line);
        }

        private void FocusInitialControl()
        {
            if (CurrentMode() == PasswordVaultStorageMode.Aes256 && File.Exists(pathBox.Text)) passwordBox.Focus();
            else pathBox.Focus();
        }

        private void ClearPasswords()
        {
            passwordBox.Clear();
            confirmPasswordBox.Clear();
            showPasswordBox.Checked = false;
            passwordBox.UseSystemPasswordChar = true;
            confirmPasswordBox.UseSystemPasswordChar = true;
        }

        private void ShowValidation(string message, Control focusControl)
        {
            MessageBox.Show(this, message, "无法继续", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            focusControl.Focus();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ClearPasswords();
                if (openedVault != null)
                {
                    openedVault.Dispose();
                    openedVault = null;
                }
            }
            base.Dispose(disposing);
        }

        private static TextBox CreateTextBox()
        {
            return new TextBox
            {
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.White
            };
        }

        private static Label CreateSectionLabel(string text)
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

        private static RadioButton CreateModeButton(string text)
        {
            return new RadioButton
            {
                Text = text,
                Appearance = Appearance.Button,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.White,
                ForeColor = Ink,
                Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                UseVisualStyleBackColor = false
            };
        }

        private static void ApplyModeButtonAppearance(RadioButton button, bool selected)
        {
            button.BackColor = selected ? Color.FromArgb(224, 240, 234) : Color.White;
            button.ForeColor = selected ? AccentDark : Ink;
            button.FlatAppearance.BorderColor = selected ? Accent : Line;
            button.FlatAppearance.BorderSize = selected ? 2 : 1;
            button.FlatAppearance.CheckedBackColor = Color.FromArgb(224, 240, 234);
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(235, 240, 242);
        }

        private static CheckBox CreateCheckBox(string text)
        {
            return new CheckBox
            {
                Text = text,
                AutoSize = false,
                ForeColor = Ink
            };
        }

        private static Button CreatePrimaryButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Accent;
            button.ForeColor = Color.White;
            button.FlatAppearance.BorderColor = Accent;
            button.FlatAppearance.MouseOverBackColor = AccentDark;
            return button;
        }

        private static Button CreateSecondaryButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Color.White;
            button.ForeColor = Ink;
            button.FlatAppearance.BorderColor = Line;
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(235, 240, 242);
            return button;
        }

        private static Button CreateFlatButton(string text)
        {
            return new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold),
                UseVisualStyleBackColor = false
            };
        }

        private static void ApplyButtonAppearance(Button button, Color enabledBackColor,
            Color enabledForeColor, Color enabledBorderColor)
        {
            button.BackColor = button.Enabled ? enabledBackColor : DisabledBack;
            button.ForeColor = button.Enabled ? enabledForeColor : DisabledInk;
            button.FlatAppearance.BorderColor = button.Enabled ? enabledBorderColor : DisabledLine;
            button.Cursor = button.Enabled ? Cursors.Hand : Cursors.Default;
        }

        private static void SetAccessibility(Control control, string name, AccessibleRole role)
        {
            control.AccessibleName = name;
            control.AccessibleRole = role;
        }
    }
}
