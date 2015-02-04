using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KawaiiDiffGen
{
    
    public class RagExe
    {
        #region Attributes
        private byte[] Client { get; set; }
        private byte[] Output { get;  set; }
        private PEReader PEHeader { get; set; } 
        #endregion

        public IEnumerable<int> MatchPattern(String uPattern)
        {
            
            String[] pattern = { };
            var foffs = new ConcurrentStack<int>();
            var offset = -1;

            
            if (uPattern == null)
                yield return offset;
            
            pattern = uPattern.Split(' ').ToArray();
            
            Parallel.For(0, Client.Length, loffset =>
            {
     
                var matched = true;

                for (var index = 0; index <= pattern.Length-1; index++)
                {

                    switch (pattern[index])
                    {
                        case "?b":
                            index += 1;
                            break;

                        case "?w":
                            index += 2;
                            break;

                        case "?d":
                            index += 4;
                            break;

                        case "?q":
                            index += 8;
                            break;

                        default:
                            matched = Client[loffset + index].Equals(Convert.ToByte(pattern[index], 16));
                            break;
                    }
                    
                    if (!matched)
                       break;
                }

                if (matched)
                    foffs.Push(loffset);
         
            });

            while (foffs.TryPop(out offset))
                yield return offset;
            
        }

        public IEnumerable<String> FindString(String uPattern , int retSize)
        {
            var foffs = new ConcurrentStack<int>();
            var offset = -1;

            if (uPattern == null || uPattern.Equals(""))
                yield return "-1";

            byte[] pattern = Encoding.ASCII.GetBytes(uPattern);

            Parallel.For(0, Client.Length, loffset =>
            {
                var matched = true;

                for (var index = 0; index <= pattern.Length - 1; index++)
                {

                    matched = Client[loffset + index].Equals(pattern[index]);

                    if (!matched)
                        break;
                }


                if (matched)
                    foffs.Push(loffset);
 
            });

            while (foffs.TryPop(out offset))
            {

                var memoffset = BitConverter.GetBytes(offset + PEHeader.Get32BitsHeader().ImageBase + 4096);
                Array.Resize(ref memoffset, retSize); // Truncate may cause data loss, but whatever...
                 
                yield return BitConverter.ToString(memoffset).Replace("-"," ");

            }

        }

        public void OpenClient(String file)
        {
            try
            {
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read))
                {
                    Client = new byte[fs.Length];
                    fs.Read(Client, 0, (int)fs.Length);
                    PEHeader = new PEReader(new BinaryReader(fs));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.GetType().FullName);
                Console.WriteLine(ex.Message);
            }
        }



   }
}
