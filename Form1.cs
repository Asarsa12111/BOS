using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CuRSOVIK_BOS
{
    public partial class Form1 : Form
    {
        private const int MaxBlockLength = 4000;

        public Form1()
        {
            InitializeComponent();
            txtReport.Text = "Готово. Нажмите \"Запустить анализ\" для формирования отчёта.";
        }

        private async void btnAnalyze_Click(object sender, EventArgs e)
        {
            btnAnalyze.Enabled = false;
            lblStatus.Text = "Статус: выполняется анализ...";
            txtReport.Clear();

            try
            {
                string report = await Task.Run(() => BuildFullReport());
                txtReport.Text = report;
                lblStatus.Text = "Статус: анализ завершён";
            }
            catch (Exception ex)
            {
                txtReport.Text = "Ошибка выполнения анализа:\r\n" + ex;
                lblStatus.Text = "Статус: ошибка";
            }
            finally
            {
                btnAnalyze.Enabled = true;
            }
        }

        private void btnSave_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtReport.Text))
            {
                MessageBox.Show("Отчёт пуст. Сначала запустите анализ.", "Информация", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (saveFileDialog.ShowDialog(this) == DialogResult.OK)
            {
                File.WriteAllText(saveFileDialog.FileName, txtReport.Text, Encoding.UTF8);
                lblStatus.Text = "Статус: отчёт сохранён";
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            txtReport.Clear();
            lblStatus.Text = "Статус: отчёт очищен";
        }

        private string BuildFullReport()
        {
            StringBuilder sb = new StringBuilder();
            string now = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

            sb.AppendLine("=== Анализатор безопасности Windows 8.1 ===");
            sb.AppendLine("Время запуска: " + now);
            sb.AppendLine("Пользователь: " + Environment.UserName);
            sb.AppendLine("Компьютер: " + Environment.MachineName);
            sb.AppendLine("Права администратора: " + (isAdmin ? "Да" : "Нет (часть проверок может быть неполной)"));
            sb.AppendLine();

            AppendSection(sb, "1. Вид ОС",
                SafeCommand("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""),
                SafePowerShell("Get-ComputerInfo | Select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer"));

            AppendSection(sb, "2. Имя узла, рабочая группа / домен",
                SafeCommand("hostname"),
                SafeCommand("systeminfo | findstr \"Domain\""),
                SafePowerShell("Get-WmiObject Win32_ComputerSystem | Select Name, Domain"));

            AppendSection(sb, "3. Установленные обновления безопасности",
                SafePowerShell("Get-HotFix | Select HotFixID, InstalledOn | Sort-Object InstalledOn -Descending"),
                SafeCommand("wmic qfe list brief"));

            AppendSection(sb, "4. Учетные записи администраторов",
                SafeCommand("net localgroup Администраторы"),
                SafeCommand("net localgroup Administrators"),
                SafePowerShell("Get-LocalGroupMember -Group \"Administrators\""));

            AppendSection(sb, "5. Политика паролей",
                SafeCommand("net accounts"),
                "NTLM/FIPS параметры LSA:\r\n" + ReadRegistryValues(
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"),
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled")));

            AppendSection(sb, "6. Аудит системы",
                SafeCommand("auditpol /get /category:*"),
                "UAC EnableLUA:\r\n" + ReadRegistryValues(Tuple.Create(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")),
                SafeCommand("net user guest"),
                "Автовход Winlogon:\r\n" + ReadRegistryValues(
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"),
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultUserName")));

            AppendSection(sb, "7. Сетевые настройки",
                SafeCommand("ipconfig /all"),
                SafeCommand("netstat -an"),
                SafeCommand("netsh advfirewall show currentprofile"));

            AppendSection(sb, "8. Открытые ресурсы",
                SafeCommand("net share"),
                SafeCommand("net view \\\\localhost"));

            AppendSection(sb, "9. Запущенные сервисы",
                SafeCommand("sc query state= all"),
                SafePowerShell("Get-Service | Where-Object {$_.Status -eq \"Running\"} | Sort-Object Name"));

            AppendSection(sb, "10. Файловая система",
                SafeCommand("fsutil fsinfo drives"),
                SafeCommand("fsutil fsinfo statistics C:"),
                SafeCommand("icacls C:\\Windows\\System32\\config\\SAM"),
                SafeCommand("icacls C:\\Program Files"),
                SafeCommand("icacls C:\\Windows"),
                SafeCommand("icacls \"%APPDATA%\""));

            AppendSection(sb, "11. Реестр (ключевые разделы)",
                ReadKeySummary(@"HKEY_LOCAL_MACHINE\SAM"),
                ReadKeySummary(@"HKEY_LOCAL_MACHINE\SECURITY"),
                ReadKeySummary(@"HKEY_LOCAL_MACHINE\SOFTWARE"),
                ReadKeySummary(@"HKEY_LOCAL_MACHINE\SYSTEM"));

            AppendSection(sb, "12. Групповые политики",
                SafeCommand("gpresult /r"),
                SafeCommand("gpresult /h gpreport.html"));

            AppendSection(sb, "13. Дополнительные параметры",
                "FIPS и CachedLogonsCount:\r\n" + ReadRegistryValues(
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled"),
                    Tuple.Create(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")),
                SafeCommand("net user guest /active"),
                SafeCommand("cipher /recover"));

            AppendSection(sb, "14. Анализ журналов (последние события Security)",
                SafePowerShell("Get-EventLog -LogName Security -Newest 100 | Select TimeGenerated, EventID, EntryType, Message"),
                SafePowerShell("Get-EventLog -LogName Security -Newest 500 | Group-Object EventID | Sort-Object Count -Descending | Select -First 10 Name, Count"));

            AppendSection(sb, "15. Признаки сканирования портов (упрощённая эвристика)",
                BuildPortScanHeuristic());

            AppendSection(sb, "Итоговая оценка (базовые флаги риска)", BuildRiskSummary());
            sb.AppendLine("Примечание: это учебный анализатор. Для промышленного аудита нужна дополнительная проверка политик, патчей и сетевого трафика в реальном времени.");

            return sb.ToString();
        }

        private static void AppendSection(StringBuilder sb, string title, params string[] blocks)
        {
            sb.AppendLine("------------------------------------------------------------");
            sb.AppendLine(title);
            sb.AppendLine("------------------------------------------------------------");

            foreach (string block in blocks)
            {
                if (string.IsNullOrWhiteSpace(block))
                {
                    continue;
                }

                sb.AppendLine(TrimBlock(block));
                sb.AppendLine();
            }
        }

        private static string BuildRiskSummary()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("- UAC EnableLUA:");
            sb.AppendLine(FormatSimpleRegistryRisk(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", expectedNonZero: true));
            sb.AppendLine("- Автовход AutoAdminLogon:");
            sb.AppendLine(FormatSimpleRegistryRisk(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", expectedNonZero: false));
            sb.AppendLine("- CachedLogonsCount:");
            sb.AppendLine(FormatCachedLogonsRisk());
            sb.AppendLine("- FIPSAlgorithmPolicy Enabled:");
            sb.AppendLine(FormatSimpleRegistryRisk(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy", "Enabled", expectedNonZero: true, neutralAllowed: true));
            return sb.ToString();
        }

        private static string FormatCachedLogonsRisk()
        {
            object value = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", null);
            if (value == null)
            {
                return "  [INFO] Параметр не найден.";
            }

            int parsed;
            if (int.TryParse(value.ToString(), out parsed))
            {
                if (parsed > 10)
                {
                    return "  [RISK] CachedLogonsCount = " + parsed + " (слишком большой кэш).";
                }

                return "  [OK] CachedLogonsCount = " + parsed + ".";
            }

            return "  [INFO] CachedLogonsCount = " + value;
        }

        private static string FormatSimpleRegistryRisk(string keyPath, string valueName, bool expectedNonZero, bool neutralAllowed = false)
        {
            object value = Registry.GetValue(keyPath, valueName, null);
            if (value == null)
            {
                return "  [INFO] Параметр не найден.";
            }

            int parsed;
            if (!int.TryParse(value.ToString(), out parsed))
            {
                return "  [INFO] " + valueName + " = " + value;
            }

            bool looksGood = expectedNonZero ? parsed != 0 : parsed == 0;
            if (looksGood)
            {
                return "  [OK] " + valueName + " = " + parsed;
            }

            if (neutralAllowed)
            {
                return "  [WARN] " + valueName + " = " + parsed + " (возможна несоответствующая политика).";
            }

            return "  [RISK] " + valueName + " = " + parsed;
        }

        private static string BuildPortScanHeuristic()
        {
            string netstat = SafeCommand("netstat -an");
            if (netstat.StartsWith("[Ошибка запуска команды]"))
            {
                return netstat;
            }

            int synReceived = CountOccurrences(netstat, "SYN_RECEIVED");
            int established = CountOccurrences(netstat, "ESTABLISHED");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Текущее состояние netstat:");
            sb.AppendLine("  SYN_RECEIVED: " + synReceived);
            sb.AppendLine("  ESTABLISHED : " + established);

            if (synReceived > 25)
            {
                sb.AppendLine("  [WARN] Повышенное число SYN_RECEIVED. Возможна попытка сканирования/флуда.");
            }
            else
            {
                sb.AppendLine("  [OK] Критического роста SYN_RECEIVED не обнаружено.");
            }

            sb.AppendLine("Рекомендация: для точного детекта вести историю netstat с интервалом 1-5 сек.");
            return sb.ToString();
        }

        private static int CountOccurrences(string source, string token)
        {
            int index = 0;
            int count = 0;
            while (index >= 0)
            {
                index = source.IndexOf(token, index, StringComparison.OrdinalIgnoreCase);
                if (index < 0)
                {
                    break;
                }

                count++;
                index += token.Length;
            }

            return count;
        }

        private static string ReadKeySummary(string keyPath)
        {
            try
            {
                object test = Registry.GetValue(keyPath, string.Empty, null);
                return keyPath + ": доступен для чтения. Значение по умолчанию = " + (test ?? "(нет)");
            }
            catch (Exception ex)
            {
                return keyPath + ": доступ ограничен или ошибка чтения (" + ex.Message + ")";
            }
        }

        private static string ReadRegistryValues(params Tuple<string, string>[] pairs)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var pair in pairs)
            {
                try
                {
                    object value = Registry.GetValue(pair.Item1, pair.Item2, null);
                    string output = value == null ? "<не найдено>" : value.ToString();
                    sb.AppendLine(pair.Item1 + " [" + pair.Item2 + "] = " + output);
                }
                catch (Exception ex)
                {
                    sb.AppendLine(pair.Item1 + " [" + pair.Item2 + "] = <ошибка: " + ex.Message + ">");
                }
            }

            return sb.ToString();
        }

        private static string SafeCommand(string command)
        {
            return RunProcess("cmd.exe", "/c " + command);
        }

        private static string SafePowerShell(string psCommand)
        {
            string escaped = psCommand.Replace("\"", "\\\"");
            return RunProcess("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"" + escaped + "\"");
        }

        private static string RunProcess(string fileName, string arguments)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        return "[Ошибка запуска команды] Процесс не создан.";
                    }

                    string stdout = process.StandardOutput.ReadToEnd();
                    string stderr = process.StandardError.ReadToEnd();
                    process.WaitForExit(30000);

                    StringBuilder sb = new StringBuilder();
                    if (!string.IsNullOrWhiteSpace(stdout))
                    {
                        sb.AppendLine(stdout.Trim());
                    }

                    if (!string.IsNullOrWhiteSpace(stderr))
                    {
                        sb.AppendLine("stderr:");
                        sb.AppendLine(stderr.Trim());
                    }

                    return sb.Length == 0 ? "<пустой вывод>" : sb.ToString().Trim();
                }
            }
            catch (Exception ex)
            {
                return "[Ошибка запуска команды] " + ex.Message;
            }
        }

        private static string TrimBlock(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return text;
            }

            string normalized = text.Trim();
            if (normalized.Length <= MaxBlockLength)
            {
                return normalized;
            }

            return normalized.Substring(0, MaxBlockLength) +
                   "\r\n... [вывод обрезан для компактности]";
        }
    }
}
