using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Cryptography
{
    public class Utility
    {

        public static ulong GetGcd(ulong a, ulong b)
        {
            if (0 == a)
                return b;
            if (0 == b)
                return a;

            ulong min = Math.Min(a, b);
            ulong max = Math.Max(a, b);
            return GetGcd(min, max % min);

        }

        public static ulong SumMod(ulong a, ulong b, ulong mod)
        {
            while (a>mod)
            {
                a -= mod;
            }
            while (b>mod)
            {
                b -= mod;
            }
            a += b;
            while (a>mod)
            {
                a -= mod;
            }
            return a;
        }

        public static ulong MultiplyMod(ulong a, ulong b, ulong mod)
        {
            while (a > mod)
            {
                a -= mod;
            }
            while (b > mod)
            {
                b -= mod;
            }
            a += b;
            while (a > mod)
            {
                a -= mod;
            }
            return a;
        }

        public static ulong ModWithExpSum(ulong root, ulong exp1, ulong exp2,ulong mod)
        {
            exp1 = GetSquareMulti(root, exp1, mod);
            exp2 = GetSquareMulti(root, exp2, mod);
            exp1 += exp2;
            return Mod(exp1, mod);

        }

        public static ulong ModWithExpMulti(ulong root, ulong exp1, ulong exp2, ulong mod)
        {
            root = GetSquareMulti(root, exp1, mod);
            root = GetSquareMulti(root, exp2, mod);
            return root;
        }

        static ulong Mod(ulong n, ulong mod)
        {
            while (n>=mod)
            {
                n -= mod;
            }
            return n;
        }

        public static ulong GetSquareMulti(ulong root, ulong exp, ulong mod)
        {
            ulong ret = 1;
            ulong u = Mod(root, mod);
            while (exp > 0)
            {
                if ((exp & 1) > 0)
                {
                    ret = Mod((ret * u), mod);

                }
                u = Mod((u * u), mod);

                exp >>= 1;
            }
            return ret;
        }

        public static bool IsPrime(ulong n)
        {
            if (0==n%2)
            {
                return false;
            }
            if (0==n%10||5==n%10)
            {
                return false;
            }
            if (0==n%7)
            {
                return false;
            }
            ulong sum = 0;
            while (n>0)
            {
                sum += n % 10;
                n /= 10;
            }
            if (0==sum%3)
            {
                return false;
            }
            return true;

        }

        public static ulong GetInverse(ulong target, ulong modular)
        {

            ulong originalModular = modular;
            if (target > modular)
            {
                return Mod(target, modular);
            }

            ulong temp = 0;
            List<ulong> quotient = new List<ulong>();
            while (target > 1)
            {
                quotient.Add(modular / target);
                temp = Mod(modular,target);
                modular = target;
                target = temp;

            }
            temp = 0;
            ulong ret = 1;
            for (int i = quotient.Count - 1; i > -1; --i)
            {
                temp = quotient[i] * ret + temp;
                Swap(ref temp, ref ret);

            }
            if (0 == quotient.Count % 2)
            {
                return ret;
            }
            return originalModular - ret;

        }

        static void Swap(ref ulong a, ref ulong b)
        {
            ulong temp = a;
            a = b;
            b = temp;

        }

        public static ulong GetMinGenerator(ulong p)
        {
            ulong mod = p;
            ulong mod1 = p - 1;
            p -= 1;
            ulong divisor = 2;
            List<ulong> factors = new List<ulong>();
            if (0 == p % 2)
            {
                factors.Add(2);
                p /= 2;
                ++divisor;
            }
            while (0 == p % 2)
            {
                p /= 2;
            }
            double temp = Math.Sqrt(mod);
            while (divisor <= temp)
            {
                if (0 == Mod(p,divisor))
                {
                    factors.Add(divisor);
                    p /= divisor;
                }
                divisor += 2;
            }

            bool isOne = false;
            for (uint i = 2; i < mod1; i++)
            {
                foreach (var item in factors)
                {
                    if (1 == GetSquareMulti(i, mod1 / item, mod))
                    {
                        isOne = true;
                        break;
                    }
                }
                if (isOne)
                {
                    isOne = false;
                    continue;
                }
                return i;
            }
            foreach (var item in factors)
            {
                Console.WriteLine("factor: " + item);
            }
            return 0;
        }

        public static ulong CalculateSharedKey(ulong p, ulong a = 51, ulong b = 92)
        {
            ulong g = GetMinGenerator(p);
            //long a = 51;
            //long b = 92;

            ulong aliceMessage = GetSquareMulti(g, a, p);
            ulong bobMessage = GetSquareMulti(g, b, p);

            ulong aliceKey = GetSquareMulti(bobMessage, a, p);
            ulong bobKey = GetSquareMulti(aliceMessage, b, p);

            if (aliceKey==bobKey)
            {
                return aliceKey;
            }
            return 0;
        }

        public static ulong GetElGamalPb(ulong p,ulong b)
        {
            ulong g = GetMinGenerator(p);
            return GetSquareMulti(g, b, p);
        }

        public static Tuple<ulong, ulong> ElGamalEncrypt(ulong message, ulong p, ulong ka, ulong pb)
        {
            if (message >= p)
            {
                return null;
            }
            ulong g = GetMinGenerator(p);
            ulong k = GetRandomNumber();
            ulong M = GetSquareMulti(pb, k, p);
            ulong C = MultiplyMod(message, M, p);
            ulong H = GetSquareMulti(g, k, p);
            Tuple<ulong, ulong> tuple = new Tuple<ulong, ulong>(C, H);
            return tuple;
        }

        public static ulong ElGamalDecrypt(ulong p, ulong C, ulong H, ulong b)
        {
            ulong q = p - 1 - b;
            ulong R = GetSquareMulti(H, q, p);
            ulong D = MultiplyMod(C, R, p);
            return D;
        }

        public static ulong ElGamalDecrypt(ulong p, Tuple<ulong,ulong> tuple, ulong b)
        {
            ulong q = p - 1 - b;
            ulong R = GetSquareMulti(tuple.Item2, q, p);
            ulong D = MultiplyMod(tuple.Item1, R, p);
            return D;
        }

        static ulong GetRandomNumber()
        {
            Random random = new Random(GetRandomSeed());
            ulong ret = (ulong)random.Next(1, 100);
            return ret;
        }

        static int GetRandomSeed()
        {
            return Convert.ToInt32(Regex.Match(Guid.NewGuid().ToString(), @"\d+").Value);

        }

    }
}
