using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace PdfPasswordRecovery
{
    internal sealed class PasswordManagerForm : Form
    {
        private static readonly Color Canvas = Color.FromArgb(244, 246, 248);
        private static readonly Color Ink = Color.FromArgb(31, 41, 48);
        private static readonly Color Muted = Color.FromArgb(102, 113, 121);
        private static readonly Color Line = Color.FromArgb(213, 220, 225);
        private static readonly Color Accent = Color.FromArgb(24, 121, 93);
        private static readonly Color AccentDark = Color.FromArgb(17, 91, 71);
        private static readonly Color Danger = Color.FromArgb(177, 55, 55);
        private static readonly Color DisabledBack = Color.FromArgb(226, 231, 234);
        private static readonly Color DisabledInk = Color.FromArgb(126, 136, 143);
        private static readonly Color DisabledLine = Color.FromArgb(196, 204, 209);
        private const string EmptyPasswordDisplay = "（空密码）";
        private const string MaskedPasswordDisplay = "********";

        private readonly PasswordVault vault;
        private readonly PasswordRecord currentResult;
        private List<PasswordRecord> records = new List<PasswordRecord>();

        private readonly TextBox searchBox = new TextBox();
        private readonly Button clearSearchButton = CreateSecondaryButton("×");
        private readonly Button newButton = CreateSecondaryButton("新增");
        private readonly Button saveCurrentButton = CreatePrimaryButton("保存当前结果");
        private readonly DataGridView recordsGrid = new DataGridView();

        private readonly Label editorTitleLabel = new Label();
        private readonly TextBox filePathBox = new TextBox();
        private readonly Button browsePdfButton = CreateSecondaryButton("选择");
        private readonly TextBox passwordBox = new TextBox();
        private readonly CheckBox emptyPasswordBox = CreateCheckBox("空密码");
        private readonly ComboBox matchBox = CreateComboBox();
        private readonly ComboBox encodingBox = CreateComboBox();
        private readonly TextBox noteBox = new TextBox();
        private readonly Button cancelEditButton = CreateSecondaryButton("取消编辑");
        private readonly Button saveEditButton = CreatePrimaryButton("保存条目");

        private readonly Label footerInfoLabel = new Label();
        private readonly CheckBox showPasswordsBox = CreateCheckBox("显示密码");
        private readonly Button copyButton = CreateSecondaryButton("复制");
        private readonly Button editButton = CreateSecondaryButton("编辑");
        private readonly Button deleteButton = CreateDangerButton("删除");
        private readonly Button closeButton = CreateSecondaryButton("关闭");
        private readonly Timer clipboardTimer = new Timer();

        private EditorMode editorMode;
        private PasswordRecord editingRecord;
        private bool editorDirty;
        private bool populatingEditor;
        private bool rebuildingGrid;
        private string passwordBeforeEmpty = String.Empty;
        private string copiedClipboardText;
        private string transientStatus = String.Empty;

        private enum EditorMode
        {
            View,
            New,
            Edit
        }

        private sealed class EncodingChoice
        {
            public readonly string Label;
            public readonly int CodePage;

            public EncodingChoice(string label, int codePage)
            {
                Label = label;
                CodePage = codePage;
            }

            public override string ToString()
            {
                return Label;
            }
        }

        public PasswordManagerForm(PasswordVault vault, PasswordRecord currentResult,
            List<PasswordRecord> initialRecords)
        {
            if (vault == null) throw new ArgumentNullException("vault");
            if (initialRecords == null) throw new ArgumentNullException("initialRecords");
            this.vault = vault;
            this.currentResult = currentResult == null ? null : currentResult.Clone();

            Text = "密码管理";
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(960, 600);
            MinimumSize = new Size(900, 560);
            BackColor = Canvas;
            ForeColor = Ink;
            Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            AutoScaleMode = AutoScaleMode.Dpi;
            ShowInTaskbar = false;
            MinimizeBox = false;
            DoubleBuffered = true;

            ConfigureControls();
            Controls.Add(BuildLayout());
            ConfigureAccessibility();
            WireEvents();
            ApplyRecords(initialRecords, null);
            SetEditorMode(EditorMode.View, null);
        }

        private void ConfigureControls()
        {
            searchBox.BorderStyle = BorderStyle.FixedSingle;
            searchBox.Dock = DockStyle.Fill;
            searchBox.Margin = new Padding(0, 2, 6, 2);

            clearSearchButton.Dock = DockStyle.Fill;
            clearSearchButton.Margin = new Padding(0, 2, 0, 2);
            clearSearchButton.Font = new Font("Segoe UI", 11F, FontStyle.Regular);
            newButton.Dock = DockStyle.Fill;
            saveCurrentButton.Dock = DockStyle.Fill;

            ConfigureGrid();

            editorTitleLabel.Text = "条目详情";
            editorTitleLabel.Dock = DockStyle.Fill;
            editorTitleLabel.TextAlign = ContentAlignment.MiddleLeft;
            editorTitleLabel.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
            editorTitleLabel.ForeColor = Ink;

            filePathBox.BorderStyle = BorderStyle.FixedSingle;
            filePathBox.BackColor = Color.White;
            filePathBox.Dock = DockStyle.Fill;
            filePathBox.Margin = new Padding(0, 3, 6, 3);
            browsePdfButton.Dock = DockStyle.Fill;
            browsePdfButton.Margin = new Padding(0, 2, 0, 2);

            passwordBox.BorderStyle = BorderStyle.FixedSingle;
            passwordBox.BackColor = Color.White;
            passwordBox.Dock = DockStyle.Fill;
            passwordBox.Margin = new Padding(0, 3, 6, 3);
            passwordBox.Font = new Font("Consolas", 10F);
            passwordBox.UseSystemPasswordChar = true;
            emptyPasswordBox.Dock = DockStyle.Fill;
            emptyPasswordBox.Margin = new Padding(2, 5, 0, 0);

            matchBox.Items.AddRange(new object[] { "用户密码", "所有者密码" });
            matchBox.SelectedIndex = 0;
            AddEncodingChoice("UTF-8", 65001);
            AddEncodingChoice("GB18030", 54936);
            AddEncodingChoice("Latin-1", 28591);
            if (Encoding.Default.CodePage != 65001 && Encoding.Default.CodePage != 54936 &&
                Encoding.Default.CodePage != 28591)
                AddEncodingChoice("系统 ANSI", Encoding.Default.CodePage);
            encodingBox.SelectedIndex = 0;

            noteBox.BorderStyle = BorderStyle.FixedSingle;
            noteBox.BackColor = Color.White;
            noteBox.Dock = DockStyle.Fill;
            noteBox.Multiline = true;
            noteBox.ScrollBars = ScrollBars.Vertical;
            noteBox.AcceptsReturn = true;
            noteBox.Margin = new Padding(0, 4, 0, 4);

            footerInfoLabel.Dock = DockStyle.Fill;
            footerInfoLabel.TextAlign = ContentAlignment.MiddleLeft;
            footerInfoLabel.ForeColor = Muted;
            footerInfoLabel.AutoEllipsis = true;

            clipboardTimer.Interval = 30000;
        }

        private void ConfigureGrid()
        {
            recordsGrid.Dock = DockStyle.Fill;
            recordsGrid.BackgroundColor = Color.White;
            recordsGrid.BorderStyle = BorderStyle.FixedSingle;
            recordsGrid.AllowUserToAddRows = false;
            recordsGrid.AllowUserToDeleteRows = false;
            recordsGrid.AllowUserToResizeRows = false;
            recordsGrid.AutoGenerateColumns = false;
            recordsGrid.MultiSelect = false;
            recordsGrid.ReadOnly = true;
            recordsGrid.RowHeadersVisible = false;
            recordsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            recordsGrid.ColumnHeadersHeight = 32;
            recordsGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            recordsGrid.RowTemplate.Height = 30;
            recordsGrid.EnableHeadersVisualStyles = false;
            recordsGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(238, 242, 244);
            recordsGrid.ColumnHeadersDefaultCellStyle.ForeColor = Ink;
            recordsGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(238, 242, 244);
            recordsGrid.ColumnHeadersDefaultCellStyle.SelectionForeColor = Ink;
            recordsGrid.DefaultCellStyle.BackColor = Color.White;
            recordsGrid.DefaultCellStyle.ForeColor = Ink;
            recordsGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(218, 235, 230);
            recordsGrid.DefaultCellStyle.SelectionForeColor = Ink;
            recordsGrid.GridColor = Line;

            DataGridViewTextBoxColumn fileColumn = new DataGridViewTextBoxColumn();
            fileColumn.Name = "FilePath";
            fileColumn.HeaderText = "PDF 文件";
            fileColumn.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            fileColumn.MinimumWidth = 150;

            DataGridViewTextBoxColumn passwordColumn = new DataGridViewTextBoxColumn();
            passwordColumn.Name = "Password";
            passwordColumn.HeaderText = "密码";
            passwordColumn.Width = 96;
            passwordColumn.SortMode = DataGridViewColumnSortMode.NotSortable;

            DataGridViewTextBoxColumn matchColumn = new DataGridViewTextBoxColumn();
            matchColumn.Name = "Match";
            matchColumn.HeaderText = "类型";
            matchColumn.Width = 74;
            matchColumn.SortMode = DataGridViewColumnSortMode.NotSortable;

            DataGridViewTextBoxColumn updatedColumn = new DataGridViewTextBoxColumn();
            updatedColumn.Name = "Updated";
            updatedColumn.HeaderText = "更新时间";
            updatedColumn.Width = 112;
            updatedColumn.SortMode = DataGridViewColumnSortMode.NotSortable;

            recordsGrid.Columns.AddRange(new DataGridViewColumn[]
            {
                fileColumn, passwordColumn, matchColumn, updatedColumn
            });
        }

        private Control BuildLayout()
        {
            TableLayoutPanel root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                BackColor = Canvas,
                Margin = new Padding(0)
            };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            root.Controls.Add(BuildHeader(), 0, 0);
            root.Controls.Add(BuildToolbar(), 0, 1);
            root.Controls.Add(BuildContent(), 0, 2);
            root.Controls.Add(BuildFooter(), 0, 3);
            return root;
        }

        private Control BuildHeader()
        {
            Panel header = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(29, 38, 44),
                Padding = new Padding(20, 8, 20, 7),
                Margin = new Padding(0)
            };
            Label title = new Label
            {
                Text = "密码管理",
                AutoSize = true,
                ForeColor = Color.White,
                Font = new Font("Microsoft YaHei UI", 15F, FontStyle.Bold),
                Location = new Point(18, 7)
            };
            Label subtitle = new Label
            {
                Text = FormatVaultSubtitle(),
                AutoSize = true,
                ForeColor = Color.FromArgb(184, 196, 203),
                Font = new Font("Microsoft YaHei UI", 8.5F),
                Location = new Point(21, 35)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            return header;
        }

        private Control BuildToolbar()
        {
            TableLayoutPanel toolbar = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Padding = new Padding(16, 7, 16, 7),
                ColumnCount = 6,
                RowCount = 1,
                Margin = new Padding(0)
            };
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 48));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 32));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 12));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 88));
            toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132));

            Label searchLabel = CreateFieldLabel("搜索");
            toolbar.Controls.Add(searchLabel, 0, 0);
            toolbar.Controls.Add(searchBox, 1, 0);
            toolbar.Controls.Add(clearSearchButton, 2, 0);
            toolbar.Controls.Add(newButton, 4, 0);
            toolbar.Controls.Add(saveCurrentButton, 5, 0);
            newButton.Margin = new Padding(0, 2, 6, 2);
            saveCurrentButton.Margin = new Padding(0, 2, 0, 2);
            return toolbar;
        }

        private Control BuildContent()
        {
            TableLayoutPanel content = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Canvas,
                Padding = new Padding(16, 10, 16, 10),
                ColumnCount = 3,
                RowCount = 1,
                Margin = new Padding(0)
            };
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 56));
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 1));
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 44));

            Panel listPanel = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Margin = new Padding(0, 0, 14, 0) };
            listPanel.Controls.Add(recordsGrid);
            Panel separator = new Panel { Dock = DockStyle.Fill, BackColor = Line, Margin = new Padding(0) };
            Control editor = BuildEditor();
            editor.Margin = new Padding(14, 0, 0, 0);

            content.Controls.Add(listPanel, 0, 0);
            content.Controls.Add(separator, 1, 0);
            content.Controls.Add(editor, 2, 0);
            return content;
        }

        private Control BuildEditor()
        {
            TableLayoutPanel editor = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Canvas,
                ColumnCount = 2,
                RowCount = 7,
                Padding = new Padding(0),
                Margin = new Padding(0)
            };
            editor.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 78));
            editor.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            editor.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            editor.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));

            editor.Controls.Add(editorTitleLabel, 0, 0);
            editor.SetColumnSpan(editorTitleLabel, 2);
            editor.Controls.Add(CreateFieldLabel("PDF 文件"), 0, 1);
            editor.Controls.Add(BuildFileEditor(), 1, 1);
            editor.Controls.Add(CreateFieldLabel("密码"), 0, 2);
            editor.Controls.Add(BuildPasswordEditor(), 1, 2);
            editor.Controls.Add(CreateFieldLabel("类型"), 0, 3);
            matchBox.Dock = DockStyle.Fill;
            matchBox.Margin = new Padding(0, 4, 0, 4);
            editor.Controls.Add(matchBox, 1, 3);
            editor.Controls.Add(CreateFieldLabel("密码编码"), 0, 4);
            encodingBox.Dock = DockStyle.Fill;
            encodingBox.Margin = new Padding(0, 4, 0, 4);
            editor.Controls.Add(encodingBox, 1, 4);
            Label noteLabel = CreateFieldLabel("备注");
            noteLabel.TextAlign = ContentAlignment.TopLeft;
            noteLabel.Padding = new Padding(0, 8, 0, 0);
            editor.Controls.Add(noteLabel, 0, 5);
            editor.Controls.Add(noteBox, 1, 5);
            editor.Controls.Add(BuildEditorActions(), 0, 6);
            editor.SetColumnSpan(editor.GetControlFromPosition(0, 6), 2);
            return editor;
        }

        private Control BuildFileEditor()
        {
            TableLayoutPanel row = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
            row.Controls.Add(filePathBox, 0, 0);
            row.Controls.Add(browsePdfButton, 1, 0);
            return row;
        }

        private Control BuildPasswordEditor()
        {
            TableLayoutPanel row = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 82));
            row.Controls.Add(passwordBox, 0, 0);
            row.Controls.Add(emptyPasswordBox, 1, 0);
            return row;
        }

        private Control BuildEditorActions()
        {
            FlowLayoutPanel actions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false,
                Padding = new Padding(0, 7, 0, 3),
                Margin = new Padding(0)
            };
            saveEditButton.Size = new Size(102, 34);
            cancelEditButton.Size = new Size(92, 34);
            saveEditButton.Margin = new Padding(6, 0, 0, 0);
            cancelEditButton.Margin = new Padding(6, 0, 0, 0);
            actions.Controls.Add(saveEditButton);
            actions.Controls.Add(cancelEditButton);
            return actions;
        }

        private Control BuildFooter()
        {
            TableLayoutPanel footer = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Padding = new Padding(16, 9, 16, 9),
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0)
            };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.Controls.Add(footerInfoLabel, 0, 0);
            footer.Controls.Add(BuildFooterActions(), 1, 0);
            return footer;
        }

        private Control BuildFooterActions()
        {
            FlowLayoutPanel actions = new FlowLayoutPanel
            {
                AutoSize = true,
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Margin = new Padding(0)
            };
            showPasswordsBox.Size = new Size(92, 34);
            showPasswordsBox.Margin = new Padding(0, 5, 4, 0);
            Button[] buttons = new Button[] { copyButton, editButton, deleteButton, closeButton };
            for (int i = 0; i < buttons.Length; i++)
            {
                buttons[i].Size = new Size(76, 34);
                buttons[i].Margin = new Padding(4, 0, 0, 0);
            }
            actions.Controls.Add(showPasswordsBox);
            actions.Controls.Add(copyButton);
            actions.Controls.Add(editButton);
            actions.Controls.Add(deleteButton);
            actions.Controls.Add(closeButton);
            return actions;
        }

        private void ConfigureAccessibility()
        {
            SetAccessibility(searchBox, "搜索密码条目，不搜索密码内容", AccessibleRole.Text);
            SetAccessibility(clearSearchButton, "清除搜索", AccessibleRole.PushButton);
            SetAccessibility(newButton, "新增密码条目", AccessibleRole.PushButton);
            SetAccessibility(saveCurrentButton, "保存当前恢复结果到密码库", AccessibleRole.PushButton);
            SetAccessibility(recordsGrid, "密码条目列表", AccessibleRole.Table);
            SetAccessibility(filePathBox, "PDF 文件路径", AccessibleRole.Text);
            SetAccessibility(browsePdfButton, "浏览 PDF 文件", AccessibleRole.PushButton);
            SetAccessibility(passwordBox, "密码", AccessibleRole.Text);
            SetAccessibility(emptyPasswordBox, "这是空密码", AccessibleRole.CheckButton);
            SetAccessibility(matchBox, "密码类型", AccessibleRole.ComboBox);
            SetAccessibility(encodingBox, "密码编码", AccessibleRole.ComboBox);
            SetAccessibility(noteBox, "密码条目备注", AccessibleRole.Text);
            SetAccessibility(cancelEditButton, "取消编辑密码条目", AccessibleRole.PushButton);
            SetAccessibility(saveEditButton, "保存密码条目", AccessibleRole.PushButton);
            SetAccessibility(showPasswordsBox, "显示或隐藏密码", AccessibleRole.CheckButton);
            SetAccessibility(copyButton, "复制选中的密码", AccessibleRole.PushButton);
            SetAccessibility(editButton, "编辑选中的密码条目", AccessibleRole.PushButton);
            SetAccessibility(deleteButton, "删除选中的密码条目", AccessibleRole.PushButton);
            SetAccessibility(closeButton, "关闭密码管理", AccessibleRole.PushButton);
        }

        private void WireEvents()
        {
            searchBox.TextChanged += delegate { RefreshGrid(GetSelectedRecordId()); };
            clearSearchButton.Click += delegate { searchBox.Clear(); searchBox.Focus(); };
            newButton.Click += delegate { BeginNew(); };
            saveCurrentButton.Click += delegate { SaveCurrentResult(); };
            recordsGrid.SelectionChanged += delegate
            {
                if (!rebuildingGrid && editorMode == EditorMode.View) DisplaySelectedRecord();
                UpdateControlStates();
            };
            recordsGrid.CellDoubleClick += delegate(object sender, DataGridViewCellEventArgs e)
            {
                if (e.RowIndex >= 0) BeginEdit();
            };
            browsePdfButton.Click += delegate { BrowsePdf(); };
            saveEditButton.Click += delegate { SaveEditor(); };
            cancelEditButton.Click += delegate { CancelEditor(); };
            showPasswordsBox.CheckedChanged += delegate
            {
                UpdatePasswordDisplay();
                RefreshGrid(GetSelectedRecordId());
            };
            emptyPasswordBox.CheckedChanged += delegate { EmptyPasswordChanged(); };
            copyButton.Click += delegate { CopySelectedPassword(); };
            editButton.Click += delegate { BeginEdit(); };
            deleteButton.Click += delegate { DeleteSelected(); };
            closeButton.Click += delegate { Close(); };
            clipboardTimer.Tick += delegate { ClearClipboardIfUnchanged(); };
            FormClosing += OnFormClosing;
            Deactivate += delegate
            {
                if (showPasswordsBox.Checked) showPasswordsBox.Checked = false;
            };

            filePathBox.TextChanged += delegate { MarkEditorDirty(); };
            passwordBox.TextChanged += delegate { MarkEditorDirty(); };
            noteBox.TextChanged += delegate { MarkEditorDirty(); };
            matchBox.SelectedIndexChanged += delegate { MarkEditorDirty(); };
            encodingBox.SelectedIndexChanged += delegate { MarkEditorDirty(); };
        }

        private void ApplyRecords(List<PasswordRecord> snapshot, Guid? selectId)
        {
            records = snapshot ?? new List<PasswordRecord>();
            records.Sort(delegate(PasswordRecord left, PasswordRecord right)
            {
                return right.UpdatedUtc.CompareTo(left.UpdatedUtc);
            });
            transientStatus = String.Empty;

            PasswordRecord selected = selectId.HasValue ? FindById(selectId.Value) : null;
            if (selected != null && !MatchesSearch(selected, searchBox.Text.Trim()))
                searchBox.Clear();
            RefreshGrid(selectId);
        }

        private void RefreshGrid(Guid? selectId)
        {
            if (recordsGrid.IsDisposed) return;
            if (!selectId.HasValue) selectId = GetSelectedRecordId();
            string query = searchBox.Text.Trim();
            int visibleCount = 0;
            rebuildingGrid = true;
            recordsGrid.Rows.Clear();

            for (int i = 0; i < records.Count; i++)
            {
                PasswordRecord record = records[i];
                if (!MatchesSearch(record, query)) continue;
                int rowIndex = recordsGrid.Rows.Add(
                    DisplayFileName(record.FilePath),
                    DisplayPassword(record.Password),
                    DisplayMatch(record.Match),
                    DisplayUpdated(record.UpdatedUtc));
                recordsGrid.Rows[rowIndex].Tag = record;
                if (selectId.HasValue && record.Id == selectId.Value)
                    recordsGrid.Rows[rowIndex].Selected = true;
                visibleCount++;
            }

            if (recordsGrid.SelectedRows.Count == 0 && recordsGrid.Rows.Count > 0)
                recordsGrid.Rows[0].Selected = true;
            rebuildingGrid = false;
            UpdateFooterInfo(visibleCount);
            if (editorMode == EditorMode.View) DisplaySelectedRecord();
            UpdateControlStates();
        }

        private bool MatchesSearch(PasswordRecord record, string query)
        {
            if (query.Length == 0) return true;
            return ContainsText(record.FilePath, query) ||
                ContainsText(Path.GetFileName(record.FilePath ?? String.Empty), query) ||
                ContainsText(record.Note, query) ||
                ContainsText(DisplayMatch(record.Match), query) ||
                ContainsText(DisplayEncoding(record.PasswordEncodingCodePage), query);
        }

        private static bool ContainsText(string value, string query)
        {
            return !String.IsNullOrEmpty(value) &&
                value.IndexOf(query, StringComparison.CurrentCultureIgnoreCase) >= 0;
        }

        private void DisplaySelectedRecord()
        {
            PasswordRecord selected = GetSelectedRecord();
            PopulateEditor(selected, EditorMode.View);
        }

        private void BeginNew()
        {
            if (!ConfirmDiscardChanges()) return;
            PasswordRecord record = new PasswordRecord();
            record.PasswordEncodingCodePage = 65001;
            record.CreatedUtc = DateTime.UtcNow;
            record.UpdatedUtc = record.CreatedUtc;
            PopulateEditor(record, EditorMode.New);
            filePathBox.Focus();
        }

        private void BeginEdit()
        {
            PasswordRecord selected = GetSelectedRecord();
            if (selected == null || !ConfirmDiscardChanges()) return;
            PopulateEditor(selected.Clone(), EditorMode.Edit);
            filePathBox.Focus();
            filePathBox.SelectionStart = filePathBox.TextLength;
        }

        private void PopulateEditor(PasswordRecord record, EditorMode mode)
        {
            populatingEditor = true;
            editorMode = mode;
            editingRecord = record == null ? null : record.Clone();
            editorDirty = false;
            passwordBeforeEmpty = String.Empty;

            if (record == null)
            {
                filePathBox.Clear();
                passwordBox.Clear();
                emptyPasswordBox.Checked = false;
                matchBox.SelectedIndex = 0;
                SelectEncoding(65001);
                noteBox.Clear();
            }
            else
            {
                filePathBox.Text = record.FilePath ?? String.Empty;
                string password = record.Password ?? String.Empty;
                bool emptyPasswordWasExplicit = !(mode == EditorMode.New && record.Password == null);
                emptyPasswordBox.Checked = emptyPasswordWasExplicit && password.Length == 0;
                passwordBeforeEmpty = password;
                passwordBox.Text = emptyPasswordBox.Checked ? EmptyPasswordDisplay : password;
                matchBox.SelectedIndex = MatchToIndex(record.Match);
                SelectEncoding(record.PasswordEncodingCodePage <= 0 ? 65001 : record.PasswordEncodingCodePage);
                noteBox.Text = record.Note ?? String.Empty;
            }
            populatingEditor = false;
            SetEditorMode(mode, record);
            UpdatePasswordDisplay();
        }

        private void SetEditorMode(EditorMode mode, PasswordRecord record)
        {
            editorMode = mode;
            bool editing = mode != EditorMode.View;
            editorTitleLabel.Text = mode == EditorMode.New ? "新增条目" :
                mode == EditorMode.Edit ? "编辑条目" : "条目详情";
            filePathBox.ReadOnly = !editing;
            passwordBox.ReadOnly = !editing;
            noteBox.ReadOnly = !editing;
            browsePdfButton.Enabled = editing;
            emptyPasswordBox.Enabled = editing;
            matchBox.Enabled = editing;
            encodingBox.Enabled = editing;
            saveEditButton.Visible = editing;
            cancelEditButton.Visible = editing;
            recordsGrid.Enabled = !editing;
            searchBox.Enabled = !editing;
            newButton.Enabled = !editing;
            saveCurrentButton.Enabled = !editing && currentResult != null;
            passwordBox.Enabled = !(editing && emptyPasswordBox.Checked);
            UpdateControlStates();
        }

        private void SaveEditor()
        {
            if (editorMode == EditorMode.View || editingRecord == null) return;
            string filePath = filePathBox.Text.Trim();
            if (filePath.Length == 0)
            {
                ShowValidation("请选择或输入 PDF 文件路径。", filePathBox);
                return;
            }
            if (!emptyPasswordBox.Checked && passwordBox.Text.Length == 0)
            {
                ShowValidation("请输入密码，或明确勾选“空密码”。", passwordBox);
                return;
            }

            PasswordRecord record = editingRecord.Clone();
            record.FilePath = filePath;
            record.Password = emptyPasswordBox.Checked ? String.Empty : passwordBox.Text;
            record.Match = IndexToMatch(matchBox.SelectedIndex);
            record.PasswordEncodingCodePage = SelectedEncodingCodePage();
            record.Note = noteBox.Text.Trim();
            if (!EnsureDocumentFingerprint(record)) return;
            if (record.CreatedUtc == DateTime.MinValue) record.CreatedUtc = DateTime.UtcNow;
            record.UpdatedUtc = DateTime.UtcNow;
            bool updatingExisting = editorMode == EditorMode.Edit;
            if (editorMode == EditorMode.New)
            {
                PasswordRecord existing = FindEquivalentRecord(record);
                if (existing != null)
                {
                    string prompt = "已存在该 PDF 的" + DisplayMatch(record.Match) +
                        "条目。是否用当前内容更新它？";
                    if (MessageBox.Show(this, prompt, "更新现有条目", MessageBoxButtons.YesNo,
                        MessageBoxIcon.Question) != DialogResult.Yes) return;
                    record.Id = existing.Id;
                    record.CreatedUtc = existing.CreatedUtc;
                    updatingExisting = true;
                }
            }
            PersistRecord(record, updatingExisting ? "条目已更新。" : "条目已新增。");
        }

        private void SaveCurrentResult()
        {
            if (currentResult == null || !ConfirmDiscardChanges()) return;
            PasswordRecord candidate = currentResult.Clone();
            PasswordRecord existing = FindEquivalentRecord(candidate);
            if (existing != null)
            {
                string prompt = "已保存过该 PDF 的" + DisplayMatch(candidate.Match) +
                    "。是否用当前恢复结果更新该条目？";
                if (MessageBox.Show(this, prompt, "更新现有条目", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question) != DialogResult.Yes) return;
                candidate.Id = existing.Id;
                candidate.CreatedUtc = existing.CreatedUtc;
                if (String.IsNullOrWhiteSpace(candidate.Note)) candidate.Note = existing.Note;
                if (candidate.DocumentFingerprint == null) candidate.DocumentFingerprint = existing.DocumentFingerprint;
            }
            else
            {
                candidate.Id = Guid.Empty;
                candidate.CreatedUtc = DateTime.UtcNow;
            }
            candidate.UpdatedUtc = DateTime.UtcNow;
            PersistRecord(candidate, "当前恢复结果已保存。" );
        }

        private void PersistRecord(PasswordRecord record, string successMessage)
        {
            try
            {
                PasswordVaultMutationResult result = vault.UpsertWithSnapshot(record);
                if (result == null || result.SavedRecord == null || result.Records == null)
                    throw new InvalidOperationException("密码库未返回已保存的条目。");
                ApplyRecords(result.Records, result.SavedRecord.Id);
                PopulateEditor(FindById(result.SavedRecord.Id), EditorMode.View);
                SetStatus(successMessage);
            }
            catch (Exception ex)
            {
                SetStatus("保存失败");
                MessageBox.Show(this, "无法保存密码条目。\r\n\r\n" + ex.Message,
                    "保存失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CancelEditor()
        {
            if (!ConfirmDiscardChanges()) return;
            editorDirty = false;
            PopulateEditor(GetSelectedRecord(), EditorMode.View);
        }

        private bool ConfirmDiscardChanges()
        {
            if (editorMode == EditorMode.View || !editorDirty) return true;
            return MessageBox.Show(this, "当前修改尚未保存，是否放弃？", "放弃修改",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes;
        }

        private void DeleteSelected()
        {
            PasswordRecord selected = GetSelectedRecord();
            if (selected == null || editorMode != EditorMode.View) return;
            string prompt = "确定删除“" + DisplayFileName(selected.FilePath) + "”的" +
                DisplayMatch(selected.Match) + "条目吗？";
            if (MessageBox.Show(this, prompt, "删除密码条目", MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                PasswordVaultMutationResult result = vault.DeleteWithSnapshot(selected.Id);
                if (result == null || result.Records == null)
                    throw new InvalidOperationException("密码库未返回删除后的快照。");
                ApplyRecords(result.Records, null);
                SetStatus("条目已删除。");
            }
            catch (Exception ex)
            {
                SetStatus("删除失败");
                MessageBox.Show(this, "无法删除密码条目。\r\n\r\n" + ex.Message,
                    "删除失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BrowsePdf()
        {
            using (OpenFileDialog dialog = new OpenFileDialog())
            {
                dialog.Title = "选择 PDF 文件";
                dialog.Filter = "PDF 文件 (*.pdf)|*.pdf|所有文件 (*.*)|*.*";
                dialog.CheckFileExists = true;
                if (File.Exists(filePathBox.Text)) dialog.FileName = filePathBox.Text;
                if (dialog.ShowDialog(this) == DialogResult.OK) filePathBox.Text = dialog.FileName;
            }
        }

        private void EmptyPasswordChanged()
        {
            if (populatingEditor) return;
            populatingEditor = true;
            if (emptyPasswordBox.Checked)
            {
                if (passwordBox.Text != EmptyPasswordDisplay) passwordBeforeEmpty = passwordBox.Text;
                passwordBox.Text = EmptyPasswordDisplay;
            }
            else
            {
                passwordBox.Text = passwordBeforeEmpty;
            }
            populatingEditor = false;
            passwordBox.Enabled = !(editorMode != EditorMode.View && emptyPasswordBox.Checked);
            UpdatePasswordDisplay();
            editorDirty = true;
        }

        private void UpdatePasswordDisplay()
        {
            bool empty = emptyPasswordBox.Checked;
            passwordBox.UseSystemPasswordChar = !empty && !showPasswordsBox.Checked;
            if (empty && passwordBox.Text != EmptyPasswordDisplay)
            {
                populatingEditor = true;
                passwordBox.Text = EmptyPasswordDisplay;
                populatingEditor = false;
            }
        }

        private void CopySelectedPassword()
        {
            PasswordRecord selected = GetSelectedRecord();
            if (selected == null) return;
            string password = selected.Password ?? String.Empty;
            try
            {
                clipboardTimer.Stop();
                copiedClipboardText = null;
                if (password.Length == 0)
                {
                    Clipboard.Clear();
                    SetStatus("该条目为空密码；剪贴板已清空。");
                }
                else
                {
                    Clipboard.SetText(password);
                    copiedClipboardText = password;
                    clipboardTimer.Start();
                    SetStatus("密码已复制，30 秒后自动清理。");
                }
            }
            catch (Exception ex)
            {
                SetStatus("剪贴板操作失败");
                MessageBox.Show(this, "无法访问剪贴板。\r\n\r\n" + ex.Message,
                    "复制失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ClearClipboardIfUnchanged()
        {
            clipboardTimer.Stop();
            string expected = copiedClipboardText;
            copiedClipboardText = null;
            if (String.IsNullOrEmpty(expected)) return;
            try
            {
                if (Clipboard.ContainsText() && String.Equals(Clipboard.GetText(), expected, StringComparison.Ordinal))
                {
                    Clipboard.Clear();
                    SetStatus("剪贴板中的密码已自动清理。");
                }
            }
            catch (Exception ex)
            {
                SetStatus("自动清理剪贴板失败：" + ex.Message);
            }
        }

        private void MarkEditorDirty()
        {
            if (!populatingEditor && editorMode != EditorMode.View) editorDirty = true;
        }

        private void UpdateControlStates()
        {
            bool editing = editorMode != EditorMode.View;
            bool selected = GetSelectedRecord() != null;
            clearSearchButton.Enabled = !editing && searchBox.TextLength > 0;
            newButton.Enabled = !editing;
            saveCurrentButton.Enabled = !editing && currentResult != null;
            copyButton.Enabled = !editing && selected;
            editButton.Enabled = !editing && selected;
            deleteButton.Enabled = !editing && selected;
            showPasswordsBox.Enabled = !editing && selected;
            browsePdfButton.Enabled = editing;

            ApplyButtonAppearance(clearSearchButton, Color.White, Ink, Line);
            ApplyButtonAppearance(newButton, Color.White, Ink, Line);
            ApplyButtonAppearance(saveCurrentButton, Accent, Color.White, Accent);
            ApplyButtonAppearance(copyButton, Color.White, Ink, Line);
            ApplyButtonAppearance(editButton, Color.White, Ink, Line);
            ApplyButtonAppearance(deleteButton, Color.White, Danger, Color.FromArgb(222, 172, 172));
            ApplyButtonAppearance(closeButton, Color.White, Ink, Line);
            ApplyButtonAppearance(browsePdfButton, Color.White, Ink, Line);
            ApplyButtonAppearance(cancelEditButton, Color.White, Ink, Line);
            ApplyButtonAppearance(saveEditButton, Accent, Color.White, Accent);
        }

        private PasswordRecord GetSelectedRecord()
        {
            if (recordsGrid.SelectedRows.Count == 0) return null;
            return recordsGrid.SelectedRows[0].Tag as PasswordRecord;
        }

        private Guid? GetSelectedRecordId()
        {
            PasswordRecord selected = GetSelectedRecord();
            return selected == null ? (Guid?)null : selected.Id;
        }

        private PasswordRecord FindById(Guid id)
        {
            for (int i = 0; i < records.Count; i++)
                if (records[i].Id == id) return records[i];
            return null;
        }

        private PasswordRecord FindByDocumentAndType(string filePath, PasswordMatch match)
        {
            string normalized = NormalizePath(filePath);
            for (int i = 0; i < records.Count; i++)
            {
                if (records[i].Match == match && String.Equals(NormalizePath(records[i].FilePath), normalized,
                    StringComparison.OrdinalIgnoreCase)) return records[i];
            }
            return null;
        }

        private PasswordRecord FindEquivalentRecord(PasswordRecord candidate)
        {
            if (candidate != null && candidate.DocumentFingerprint != null &&
                candidate.DocumentFingerprint.Length == 32)
            {
                for (int i = 0; i < records.Count; i++)
                {
                    if (records[i].Match == candidate.Match &&
                        FingerprintsEqual(records[i].DocumentFingerprint, candidate.DocumentFingerprint))
                        return records[i];
                }
            }
            return candidate == null ? null : FindByDocumentAndType(candidate.FilePath, candidate.Match);
        }

        private bool EnsureDocumentFingerprint(PasswordRecord record)
        {
            try
            {
                record.DocumentFingerprint = PasswordDocumentFingerprint.FromPath(record.FilePath);
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "无法生成 PDF 文档指纹。\r\n\r\n" + ex.Message,
                    "无法保存", MessageBoxButtons.OK, MessageBoxIcon.Error);
                filePathBox.Focus();
                return false;
            }
        }

        private static bool FingerprintsEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static string NormalizePath(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return String.Empty;
            try { return PasswordDocumentFingerprint.NormalizePath(path); }
            catch { return path.Trim(); }
        }

        private void UpdateFooterInfo(int visibleCount)
        {
            string count = String.IsNullOrWhiteSpace(searchBox.Text) ?
                "共 " + records.Count + " 项" : "筛选 " + visibleCount + " / " + records.Count + " 项";
            footerInfoLabel.Text = transientStatus.Length == 0 ? count : count + "  |  " + transientStatus;
        }

        private void SetStatus(string text)
        {
            transientStatus = text ?? String.Empty;
            UpdateFooterInfo(recordsGrid.Rows.Count);
        }

        private void ShowValidation(string message, Control focusControl)
        {
            MessageBox.Show(this, message, "无法保存", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            focusControl.Focus();
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!ConfirmDiscardChanges())
            {
                e.Cancel = true;
                return;
            }
            ClearClipboardIfUnchanged();
            showPasswordsBox.Checked = false;
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Control | Keys.F))
            {
                if (editorMode == EditorMode.View)
                {
                    searchBox.Focus();
                    searchBox.SelectAll();
                }
                return true;
            }
            if (keyData == Keys.Escape && editorMode != EditorMode.View)
            {
                CancelEditor();
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                clipboardTimer.Stop();
                clipboardTimer.Dispose();
            }
            base.Dispose(disposing);
        }

        private void AddEncodingChoice(string label, int codePage)
        {
            encodingBox.Items.Add(new EncodingChoice(label, codePage));
        }

        private void SelectEncoding(int codePage)
        {
            for (int i = 0; i < encodingBox.Items.Count; i++)
            {
                EncodingChoice choice = encodingBox.Items[i] as EncodingChoice;
                if (choice != null && choice.CodePage == codePage)
                {
                    encodingBox.SelectedIndex = i;
                    return;
                }
            }
            string label;
            try { label = Encoding.GetEncoding(codePage).WebName + " (" + codePage + ")"; }
            catch { label = "代码页 " + codePage; }
            AddEncodingChoice(label, codePage);
            encodingBox.SelectedIndex = encodingBox.Items.Count - 1;
        }

        private int SelectedEncodingCodePage()
        {
            EncodingChoice choice = encodingBox.SelectedItem as EncodingChoice;
            return choice == null ? 65001 : choice.CodePage;
        }

        private static int MatchToIndex(PasswordMatch match)
        {
            if (match == PasswordMatch.Owner) return 1;
            return 0;
        }

        private static PasswordMatch IndexToMatch(int index)
        {
            return index == 1 ? PasswordMatch.Owner : PasswordMatch.User;
        }

        private string DisplayPassword(string password)
        {
            if (String.IsNullOrEmpty(password)) return EmptyPasswordDisplay;
            return showPasswordsBox.Checked ? password : MaskedPasswordDisplay;
        }

        private static string DisplayFileName(string filePath)
        {
            if (String.IsNullOrWhiteSpace(filePath)) return "（未命名）";
            string name = Path.GetFileName(filePath);
            return String.IsNullOrWhiteSpace(name) ? filePath : name;
        }

        private static string DisplayMatch(PasswordMatch match)
        {
            if (match == PasswordMatch.User) return "用户密码";
            if (match == PasswordMatch.Owner) return "所有者密码";
            return "未指定";
        }

        private static string DisplayEncoding(int codePage)
        {
            if (codePage == 65001) return "UTF-8";
            if (codePage == 54936) return "GB18030";
            if (codePage == 28591) return "Latin-1";
            try { return Encoding.GetEncoding(codePage).WebName; }
            catch { return "代码页 " + codePage; }
        }

        private static string DisplayUpdated(DateTime value)
        {
            if (value == DateTime.MinValue) return String.Empty;
            DateTime local = value.Kind == DateTimeKind.Utc ? value.ToLocalTime() : value;
            return local.ToString("yyyy-MM-dd HH:mm");
        }

        private string FormatVaultSubtitle()
        {
            string mode = vault.StorageMode == PasswordVaultStorageMode.PlaintextJson ?
                "明文 JSON" : "AES-256";
            string fileName = Path.GetFileName(vault.StoragePath);
            if (String.IsNullOrWhiteSpace(fileName)) fileName = vault.StoragePath;
            return mode + "  |  " + fileName;
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

        private static ComboBox CreateComboBox()
        {
            return new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Standard
            };
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

        private static Button CreateDangerButton(string text)
        {
            Button button = CreateFlatButton(text);
            button.BackColor = Color.White;
            button.ForeColor = Danger;
            button.FlatAppearance.BorderColor = Color.FromArgb(222, 172, 172);
            button.FlatAppearance.MouseOverBackColor = Color.FromArgb(250, 235, 235);
            return button;
        }

        private static Button CreateFlatButton(string text)
        {
            return new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                FlatAppearance = { BorderSize = 1 },
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
