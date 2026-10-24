using System;
using System.Drawing;
using System.Windows.Forms;

namespace LocalVaultDesktopDemo
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var form = new Form
            {
                Text = "LocalVault Desktop Login Demo",
                StartPosition = FormStartPosition.CenterScreen,
                ClientSize = new Size(430, 285),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var heading = new Label
            {
                Text = "LocalVault desktop autofill test",
                AutoSize = true,
                Font = new Font("Segoe UI", 14F, FontStyle.Bold),
                Location = new Point(28, 24)
            };
            var explanation = new Label
            {
                Text = "This local demo never sends credentials anywhere.",
                AutoSize = true,
                Font = new Font("Segoe UI", 9F),
                Location = new Point(30, 60)
            };
            var userLabel = new Label
            {
                Text = "Username",
                AutoSize = true,
                Location = new Point(30, 98)
            };
            var username = new TextBox
            {
                Name = "UsernameTextBox",
                AccessibleName = "Username",
                Location = new Point(30, 118),
                Size = new Size(365, 25),
                TabIndex = 0
            };
            var passwordLabel = new Label
            {
                Text = "Password",
                AutoSize = true,
                Location = new Point(30, 153)
            };
            var password = new TextBox
            {
                Name = "PasswordTextBox",
                AccessibleName = "Password",
                Location = new Point(30, 173),
                Size = new Size(365, 25),
                UseSystemPasswordChar = true,
                TabIndex = 1
            };
            var submit = new Button
            {
                Text = "Sign in (local demo)",
                Location = new Point(245, 214),
                Size = new Size(150, 32),
                TabIndex = 2
            };
            var status = new Label
            {
                Text = "",
                AutoSize = true,
                Location = new Point(30, 223)
            };
            submit.Click += delegate
            {
                status.Text = "Demo submission intercepted locally.";
            };

            form.Controls.Add(heading);
            form.Controls.Add(explanation);
            form.Controls.Add(userLabel);
            form.Controls.Add(username);
            form.Controls.Add(passwordLabel);
            form.Controls.Add(password);
            form.Controls.Add(submit);
            form.Controls.Add(status);
            form.AcceptButton = submit;
            Application.Run(form);
        }
    }
}
