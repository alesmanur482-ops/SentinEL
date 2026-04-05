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
    string apiKey = "YOUR_API_KEY_HERE";
    string url = $"https://www.virustotal.com/api/v3/files/{parmakIzi}";

    using (HttpClient istemci = new HttpClient())
    {
        istemci.DefaultRequestHeaders.Add("x-apikey", apiKey);
        Console.WriteLine("[İNTERNET] Sorgulanıyor...");

        var cevap = istemci.GetAsync(url).Result;

        if (cevap.IsSuccessStatusCode)
        {
            Console.WriteLine("✔ DOSYA VERİ TABANINDA VAR!");
        } else
        {
            Console.WriteLine("[-] Dosya yeni veya bulunamadı.");
        }
    }
}

else
{      
    Console.WriteLine("\n[HATA] Dosya bulunamadı! Lütfen yolu kontrol edin.");
}