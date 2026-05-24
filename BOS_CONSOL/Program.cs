using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace Win81SecurityScanner
{
    // Вспомогательные методы вывода и выполнения команд
    public static class Utils
    {
        public static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static string RunCommand(string exe, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(10000);
                    return p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                }
            }
            catch (Exception ex) { return $"[Ошибка выполнения]: {ex.Message}"; }
        }

        public static void PrintHeader(string title)
        {
            Console.WriteLine($"\n🔹 {title}");
            Console.WriteLine(new string('-', 50));
        }

        public static void PrintInfo(string msg)
        {
            Console.WriteLine($"ℹ {msg}");
        }

        public static void PrintWarning(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"⚠ {msg}");
            Console.ResetColor();
        }

        public static void PrintDanger(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"❌ {msg}");
            Console.ResetColor();
        }

        public static void PrintSuccess(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✅ {msg}");
            Console.ResetColor();
        }

        public static void PrintRec(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"💡 РЕКОМЕНДАЦИЯ: {msg}");
            Console.ResetColor();
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "Сканер безопасности ОС Windows 8.1";

            if (!Utils.IsAdministrator())
            {
                Utils.PrintWarning("⚠ Программа запущена без прав администратора. Некоторые проверки будут ограничены.");
                Console.WriteLine("Для полного анализа перезапустите консоль от имени Администратора.\n");
            }

            bool exit = false;
            while (!exit)
            {
                ShowMenu();
                string choice = Console.ReadLine()?.Trim().ToLower();
                Console.Clear();

                switch (choice)
                {
                    case "1": Scanner.CheckOSInfo(); break;
                    case "2": Scanner.CheckHostInfo(); break;
                    case "3": Scanner.CheckUpdates(); break;
                    case "4": Scanner.CheckAdminAccounts(); break;
                    case "5": Scanner.CheckPasswordPolicy(); break;
                    case "6": Scanner.CheckAuditPolicy(); break;
                    case "7": Scanner.CheckNetworkSettings(); break;
                    case "8": Scanner.CheckSharedResources(); break;
                    case "9": Scanner.CheckRunningServices(); break;
                    case "10": Scanner.CheckFileSystem(); break;
                    case "11": Scanner.CheckRegistryPermissions(); break;
                    case "12": Scanner.CheckGroupPolicies(); break;
                    case "13": Scanner.CheckAdditionalParams(); break;
                    case "14": Scanner.CheckLogs(); break;
                    case "15": Scanner.CheckPortScanDetection(); break;
                    case "0": exit = true; Utils.PrintInfo("Выход из программы..."); break;
                    case "a": RunAllChecks(); break;
                    default: Utils.PrintWarning("Неверный выбор. Попробуйте снова."); break;
                }

                if (!exit)
                {
                    Console.WriteLine("\nНажмите любую клавишу для возврата в меню...");
                    Console.ReadKey();
                    Console.Clear();
                }
            }
        }

        static void ShowMenu()
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
            Console.WriteLine("║              СКАНЕР БЕЗОПАСНОСТИ ОС WINDOWS 8.1          ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════╣");
            Console.WriteLine("║  1. Вид ОС и версия ядра                                ║");
            Console.WriteLine("║  2. Имя узла, домен/рабочая группа                      ║");
            Console.WriteLine("║  3. Установленные обновления безопасности               ║");
            Console.WriteLine("║  4. Учетные записи администраторов                      ║");
            Console.WriteLine("║  5. Политика паролей                                    ║");
            Console.WriteLine("║  6. Политика аудита системы                             ║");
            Console.WriteLine("║  7. Сетевые настройки (TCP/IP, DNS, DHCP)               ║");
            Console.WriteLine("║  8. Открытые/разделяемые ресурсы                        ║");
            Console.WriteLine("║  9. Запущенные сервисы                                  ║");
            Console.WriteLine("║ 10. Файловая система и права доступа                    ║");
            Console.WriteLine("║ 11. Разрешения реестра                                  ║");
            Console.WriteLine("║ 12. Групповые политики                                  ║");
            Console.WriteLine("║ 13. Доп. параметры (SAM, Guest, кэширование)            ║");
            Console.WriteLine("║ 14. Анализ журналов событий                             ║");
            Console.WriteLine("║ 15. Обнаружение сканирования портов                     ║");
            Console.WriteLine("╠══════════════════════════════════════════════════════════╣");
            Console.WriteLine("║  [A] Проверить всё   |   [0] Выход                      ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
            Console.Write("Выберите пункт: ");
        }

        static void RunAllChecks()
        {
            Utils.PrintInfo("🔄 Запуск полного сканирования...");
            Scanner.CheckOSInfo();
            Scanner.CheckHostInfo();
            Scanner.CheckUpdates();
            Scanner.CheckAdminAccounts();
            Scanner.CheckPasswordPolicy();
            Scanner.CheckAuditPolicy();
            Scanner.CheckNetworkSettings();
            Scanner.CheckSharedResources();
            Scanner.CheckRunningServices();
            Scanner.CheckFileSystem();
            Scanner.CheckRegistryPermissions();
            Scanner.CheckGroupPolicies();
            Scanner.CheckAdditionalParams();
            Scanner.CheckLogs();
            Scanner.CheckPortScanDetection();
            Utils.PrintSuccess("✅ Сканирование завершено.");
        }
    }

    static class Scanner
    {
        // 1. Вид ОС
        public static void CheckOSInfo()
        {
            Utils.PrintHeader("1. Информация об ОС");
            Console.WriteLine($"Версия Windows: {Environment.OSVersion}");
            Console.WriteLine($"Архитектура: {(Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit")}");

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (key != null)
                {
                    Console.WriteLine($"Имя продукта: {key.GetValue("ProductName")}");
                    Console.WriteLine($"Сборка: {key.GetValue("CurrentBuildNumber")}");
                    Console.WriteLine($"Редакция: {key.GetValue("EditionID")}");
                }
            }
            Utils.PrintRec("Убедитесь, что установлены все накопительные обновления для Windows 8.1 (вплоть до KB4534310).");
        }

        // 2. Имя узла, домен/группа
        public static void CheckHostInfo()
        {
            Utils.PrintHeader("2. Сетевая идентификация");
            Console.WriteLine($"Имя компьютера: {Environment.MachineName}");
            Console.WriteLine($"Домен/Группа: {Environment.UserDomainName}");
            Console.WriteLine($"Тип системы: {(Environment.UserInteractive ? "Интерактивная" : "Служебная")}");
            Utils.PrintRec("В корпоративной среде ПК должен входить в домен Active Directory, а не в WORKGROUP.");
        }

        // 3. Обновления
        public static void CheckUpdates()
        {
            Utils.PrintHeader("3. Установленные обновления");
            string output = Utils.RunCommand("wmic", "qfe list brief /format:list");
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int count = lines.Length;
            Console.WriteLine($"Найдено установленных патчей/обновлений: {count}");
            if (count < 50)
                Utils.PrintWarning("Критически мало обновлений. Установите последние патчи из Центра обновления.");
            else
                Utils.PrintSuccess("Обновления присутствуют в достаточном количестве.");
            Utils.PrintRec("Включите автоматическую установку обновлений безопасности (Windows Update).");
        }

        // 4. Администраторы
        public static void CheckAdminAccounts()
        {
            Utils.PrintHeader("4. Учетные записи администраторов");
            string output = Utils.RunCommand("net", "localgroup Администраторы");
            Console.WriteLine(output);

            bool guestInAdmin = output.Contains("Гость") || output.Contains("Guest");
            if (guestInAdmin)
                Utils.PrintDanger("Гостевая учетная запись входит в группу администраторов! Критическая ошибка.");

            int admins = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                               .Count(l => l.Trim().Length > 0 && !l.Contains("Алиасы") && !l.Contains("Члены") && !l.Contains("Команда") && !l.Contains("Успешно"));
            Utils.PrintRec($"Активных администраторов: {admins}. Рекомендуется оставить не более 2-3 учетных записей.");
        }

        // 5. Политика паролей
        public static void CheckPasswordPolicy()
        {
            Utils.PrintHeader("5. Политика паролей");
            string output = Utils.RunCommand("net", "accounts");
            Console.WriteLine(output);

            if (output.Contains("Минимальная длина пароля: 0") || output.Contains("Minimum password length: 0"))
                Utils.PrintDanger("Минимальная длина пароля = 0! Это критическая уязвимость.");
            if (!output.Contains("Пароли должны отвечать требованиям сложности: Да") &&
                !output.Contains("Password complexity: Enabled"))
                Utils.PrintWarning("Сложность паролей отключена.");
            Utils.PrintRec("Мин. длина: 8+ символов, сложность: ВКЛ, срок действия: 42-90 дней, история: 5-24 паролей.");
        }

        // 6. Аудит
        public static void CheckAuditPolicy()
        {
            Utils.PrintHeader("6. Политика аудита");
            string output = Utils.RunCommand("auditpol", "/get /category:*");
            Console.WriteLine(output);

            if (!output.Contains("Вход в систему") && !output.Contains("Logon/Logoff"))
                Utils.PrintWarning("Ключевые категории аудита отключены или выведены некорректно.");
            Utils.PrintRec("Включите аудит: Вход/Выход, Изменение политик, Управление учетными записями, Доступ к объектам.");
        }

        // 7. Сетевые настройки
        public static void CheckNetworkSettings()
        {
            Utils.PrintHeader("7. Сетевые настройки");
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

            foreach (var ni in interfaces)
            {
                Console.WriteLine($"Интерфейс: {ni.Name} ({ni.NetworkInterfaceType})");
                var ipProps = ni.GetIPProperties();
                foreach (var ua in ipProps.UnicastAddresses)
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        Console.WriteLine($"  IPv4: {ua.Address}");
                foreach (var dns in ipProps.DnsAddresses)
                    Console.WriteLine($"  DNS: {dns}");
                try
                {
                    var v4 = ipProps.GetIPv4Properties();
                    Console.WriteLine($"  DHCP: {(v4.IsDhcpEnabled ? "Включен" : "Статический")}");
                }
                catch { }
            }
            Utils.PrintRec("Используйте статические DNS или доверенные серверы. Отключите IPv6, если он не используется.");
        }

        // 8. Общие ресурсы
        public static void CheckSharedResources()
        {
            Utils.PrintHeader("8. Разделяемые ресурсы (NetBIOS Shares)");
            string output = Utils.RunCommand("net", "share");
            Console.WriteLine(output);
            if (output.Contains("ADMIN$") || output.Contains("C$"))
                Utils.PrintWarning("Обнаружены скрытые административные шары. Рекомендуется отключить, если не используются.");
            Utils.PrintRec("Отключите `AutoShareServer` и `AutoShareWks` в реестре, если шары не нужны.");
        }

        // 9. Сервисы
        public static void CheckRunningServices()
        {
            Utils.PrintHeader("9. Запущенные сервисы");
            string output = Utils.RunCommand("sc", "query state= all type= service");
            var lines = output.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
            int running = lines.Count(l => l.Contains("STATE") && l.Contains("RUNNING"));
            Console.WriteLine($"Активных служб: {running}");
            Utils.PrintRec("Отключите: SSDP, UPnP, RemoteRegistry, Telnet, Print Spooler (если нет принтеров), если они не требуются.");
        }

        // 10. Файловая система
        public static void CheckFileSystem()
        {
            Utils.PrintHeader("10. Файловая система");
            var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed);
            foreach (var d in drives)
            {
                Console.WriteLine($"Диск {d.Name} | Тип: {d.DriveFormat} | Свободно: {d.AvailableFreeSpace / 1024 / 1024 / 1024} ГБ");
                if (d.DriveFormat != "NTFS")
                    Utils.PrintWarning($"Диск {d.Name} не использует NTFS! Это ограничивает права доступа и шифрование.");
            }
            string critical = @"C:\Windows\System32\cmd.exe";
            if (File.Exists(critical))
            {
                var acl = File.GetAccessControl(critical);
                int rules = acl.GetAccessRules(true, false, typeof(NTAccount)).Count;
                Console.WriteLine($"Права на {critical}: {rules} правил ACL");
            }
            Utils.PrintRec("Все системные разделы должны быть в NTFS. Ограничьте права на System32 для группы Users.");
        }

        // 11. Реестр
        public static void CheckRegistryPermissions()
        {
            Utils.PrintHeader("11. Разрешения реестра");
            string[] criticalKeys = { @"SYSTEM\CurrentControlSet\Control", @"SAM\SAM" };
            foreach (var k in criticalKeys)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(k))
                    {
                        if (key != null)
                        {
                            var sec = key.GetAccessControl();
                            int rules = sec.GetAccessRules(true, false, typeof(NTAccount)).Count;
                            Console.WriteLine($"[{k}] Правил доступа: {rules}");
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"[{k}] Требуется доступ SYSTEM/Administrator.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[{k}] Ошибка: {ex.Message}");
                }
            }
            Utils.PrintRec("Ключи SAM, SECURITY, SYSTEM должны иметь доступ только для SYSTEM и Administrators (Full Control).");
        }

        // 12. Групповые политики
        public static void CheckGroupPolicies()
        {
            Utils.PrintHeader("12. Групповые политики");
            string output = Utils.RunCommand("gpresult", "/r");
            string preview = output.Length > 1500 ? output.Substring(0, 1500) + "..." : output;
            Console.WriteLine(preview);
            if (output.Contains("Непримененные групповые политики"))
                Utils.PrintWarning("Есть политики, которые не применились к компьютеру или пользователю.");
            Utils.PrintRec("Используйте `rsop.msc` для детального анализа. Убедитесь, что политики безопасности применяются.");
        }

        // 13. Доп. параметры
        public static void CheckAdditionalParams()
        {
            Utils.PrintHeader("13. Дополнительные параметры безопасности");
            // Кэширование входов
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
            {
                string cached = key?.GetValue("CachedLogonsCount", "10").ToString();
                Console.WriteLine($"Кэширование входов (CachedLogonsCount): {cached}");
                if (int.TryParse(cached, out int count) && count > 0)
                    Utils.PrintWarning("Кэширование учетных данных включено. Риск атаки при краже диска.");
            }
            // Гостевой вход
            string guestOut = Utils.RunCommand("net", "user Гость");
            if (guestOut.Contains("Активность учетной записи      Активна") || guestOut.Contains("Account active               Yes"))
                Utils.PrintWarning("Учетная запись Гость активна! Отключите её.");
            else
                Utils.PrintSuccess("Учетная запись Гость отключена.");

            // LM-хэши
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
            {
                int lmHash = (int)(key?.GetValue("NoLmHash", 0) ?? 0);
                Console.WriteLine($"Отключены LM-хэши (NoLmHash): {(lmHash == 1 ? "Да" : "Нет")}");
                if (lmHash != 1) Utils.PrintDanger("LM-хэши включены! Это критическая уязвимость.");
            }
            Utils.PrintRec("Установите CachedLogonsCount=0, отключите Гостя, включите NoLmHash=1.");
        }

        // 14. Журналы
        public static void CheckLogs()
        {
            Utils.PrintHeader("14. Анализ журналов событий");
            string logName = "Security";
            try
            {
                EventLog log = new EventLog(logName);
                int total = log.Entries.Count;
                Console.WriteLine($"Всего записей в журнале {logName}: {total}");

                var recent = log.Entries.Cast<EventLogEntry>()
                    .OrderByDescending(e => e.TimeGenerated)
                    .Take(10)
                    .ToList();

                foreach (var entry in recent)
                {
                    string msg = entry.Message;
                    if (msg.Length > 100) msg = msg.Substring(0, 100) + "...";
                    Console.WriteLine($"[{entry.TimeGenerated:dd.MM.yyyy HH:mm}] ID:{entry.InstanceId} | {entry.EntryType} | {msg}");
                }

                // Частые события
                var freq = log.Entries.Cast<EventLogEntry>()
                    .GroupBy(e => e.InstanceId)
                    .OrderByDescending(g => g.Count())
                    .Take(5);
                Console.WriteLine("\n🔝 Частые события (ID):");
                foreach (var f in freq) Console.WriteLine($"  ID {f.Key}: {f.Count()} раз");
            }
            catch (Exception ex)
            {
                Utils.PrintWarning($"Не удалось прочитать журнал {logName}: {ex.Message}");
            }
            Utils.PrintRec("Настройте размер журнала (мин. 100 МБ) и политику перезаписи. Мониторьте ID 4625 (отказ входа), 4728 (добавление в группу).");
        }

        // 15. Сканирование портов
        public static void CheckPortScanDetection()
        {
            Utils.PrintHeader("15. Обнаружение сканирования портов / Открытые порты");
            string netstat = Utils.RunCommand("netstat", "-ano");
            var lines = netstat.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int listening = lines.Count(l => l.Contains("LISTENING"));
            Console.WriteLine($"Прослушивающихся портов (LISTENING): {listening}");

            // Анализ firewall
            string fw = Utils.RunCommand("netsh", "advfirewall show allprofiles state");
            Console.WriteLine("Статус брандмауэра:");
            Console.WriteLine(fw.Length > 300 ? fw.Substring(0, 300) + "..." : fw);

            // Поиск в журнале безопасности признаков сканирования
            try
            {
                EventLog secLog = new EventLog("Security");
                DateTime oneHourAgo = DateTime.Now.AddHours(-1);
                int failures = secLog.Entries.Cast<EventLogEntry>()
                    .Count(e => e.TimeGenerated > oneHourAgo && (e.InstanceId == 4625 || e.InstanceId == 5156));

                if (failures > 20)
                    Utils.PrintWarning("За последний час >20 событий отказа/блокировки. Возможно сканирование или подбор паролей.");
                else
                    Utils.PrintSuccess("Признаков активного сканирования за последний час не обнаружено.");
            }
            catch { Utils.PrintWarning("Не удалось прочитать журнал Security для анализа сканирования."); }

            Utils.PrintRec("Включите брандмауэр, настройте блокировку после 5 неудачных входов, отключите ICMP-ответы при необходимости.");
        }
    }
 

}