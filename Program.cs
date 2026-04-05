using System.Security.Cryptography;
Console.WriteLine("--- SentinEL Dosya Analizi Sistemi Başlatıldı ---");
Console.WriteLine("Lütfen analiz edilecek dosyayı buraya sürükleyip ENTER'a basın:");

string? yol = Console.ReadLine()?.Replace("'", "").Replace("\"", "").Trim();
if (File.Exists(yol))
{
    string parmakIzi = "";
    using (FileStream akis = File.OpenRead(yol))
    {
        var sha = SHA256.Create();
        byte[] baytlar = sha.ComputeHash(akis);
        parmakIzi = BitConverter.ToString(baytlar).Replace("-", "").ToLower();
    }
    Console.WriteLine("Kimlik No: " + parmakIzi);
    string apiKey = "BURAYA_KENDI_API_ANAHTARINIZI_YAZIN";
    string url = $"https://www.virustotal.com/api/v3/files/{parmakIzi}";

    using (HttpClient istemci = new HttpClient())
    {
        istemci.DefaultRequestHeaders.Add("x-apikey", apiKey);
        Console.WriteLine("[İNTERNET] Sorgulanıyor...");

        var cevap = istemci.GetAsync(url).Result;
if (cevap.IsSuccessStatusCode)
{
    string icerik = cevap.Content.ReadAsStringAsync().Result;
    
    using (var belge = System.Text.Json.JsonDocument.Parse(icerik))
    {
        var root = belge.RootElement;
        var istatistik = root.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");

        int kotu = istatistik.GetProperty("malicious").GetInt32();
        int supheli = istatistik.GetProperty("suspicious").GetInt32();
        int temiz = istatistik.GetProperty("harmless").GetInt32();

        Console.WriteLine("\n---------- DETAYLI ANALİZ RAPORU ----------");
        
        if (kotu > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"!!! TEHLİKE: {kotu} adet antivirüs bu dosyayı ZARARLI buldu!");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✔ TEMİZ: Hiçbir antivirüs zararlı yazılım bulamadı.");
        }

        Console.ResetColor();
        Console.WriteLine($"Şüpheli: {supheli} | Güvenli: {temiz}");
        Console.WriteLine("-------------------------------------------");
    }
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("\n[-] BİLGİ: Dosya yeni veya henüz analiz edilmemiş (0/70).");
    Console.ResetColor();
}
 }
    }
      