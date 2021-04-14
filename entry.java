import java.math.BigInteger;
import java.util.Random;

class linear_combination
{
    public linear_combination(BigInteger s, BigInteger t)
    {
        this.s = s;
        this.t = t;
    }

    public BigInteger s;
    public BigInteger t;
}

class rsa_public_key
{
    rsa_public_key(BigInteger N, BigInteger e)
    {
        this.N = N;
        this.e = e;
    }

    public BigInteger N;
    public BigInteger e;
}

class rsa_private_key
{
    rsa_private_key(BigInteger N, BigInteger d)
    {
        this.N = N;
        this.d = d;
    }

    public BigInteger N;
    public BigInteger d;
}

class rsa_key_pair
{
    rsa_key_pair(rsa_public_key pub, rsa_private_key priv)
    {
        this.pub = pub;
        this.priv = priv;
    }

    public rsa_public_key pub;
    public rsa_private_key priv;
}

public class rsa
{
    public static BigInteger gcd(BigInteger a, BigInteger b)
    {
        if (a.compareTo(b) < 0)
        {
            BigInteger tmp = a;
            a=b;
            b=tmp;
        }

        BigInteger r = a.mod(b);
        
        while (r.compareTo(new BigInteger("0")) != 0)
        {
            a=b;
            b=r;
            r = a.mod(b);
        }
        return b;
    }

    // return a linear combination of a,b 
    // such that s*a + t*b = gcd(a,b)
    public static linear_combination extended_gcd(BigInteger a, BigInteger b)
    {
        BigInteger old_r = a;
        BigInteger r=b;

        BigInteger old_s = new BigInteger("1");
        BigInteger s = new BigInteger("0");

        BigInteger old_t = new BigInteger("0");
        BigInteger t = new BigInteger("1");

        while (r.compareTo(new BigInteger("0")) != 0)
        {
            BigInteger q = old_r.divide(r); 

            BigInteger tmp = r;
            r = old_r.subtract(q.multiply(tmp));
            old_r = tmp;

            tmp = s;
            s = old_s.subtract(q.multiply(tmp));
            old_s = tmp;

            tmp = t;
            t = old_t.subtract(q.multiply(tmp));
            old_t = tmp;
        }

        return new linear_combination(old_s, old_t);
    }

    // erweiterter euklidischer algorithmus nach vorgabe
    public static BigInteger RSA_private(BigInteger phiN, BigInteger e)
    {
        BigInteger a = phiN;
        BigInteger b=e;

        BigInteger u = new BigInteger("1");
        BigInteger t = new BigInteger("1");

        BigInteger v = new BigInteger("0");
        BigInteger s = new BigInteger("0");

        while (b.compareTo(new BigInteger("0")) > 0)
        {
            BigInteger q = a.divide(b); 

            BigInteger r = a.mod(b);
            a = b;
            b = r;

            r = u.subtract(q.multiply(s));
            u = s;
            s = r;

            r = v.subtract(q.multiply(t));
            v = t;
            t=r;
        }

        if (v.compareTo(new BigInteger("0")) < 0) 
            v = v.add(phiN);

        return v;
    }

    public static rsa_key_pair construct_rsa_keypair(BigInteger q, BigInteger p)
    {
        BigInteger N = p.multiply(q);
        BigInteger tmp1 = q.subtract(new BigInteger("1"));
        BigInteger tmp2 = p.subtract(new BigInteger("1"));

        BigInteger phiN = tmp1.multiply(tmp2);

        BigInteger e = new BigInteger("2");

        // find e such that e \in P and gcd(e,phiN)=1
        while (true)
        {
            boolean is_prime = true;
            for (BigInteger i = new BigInteger("2"); i.compareTo(e.sqrt()) < 0; i = i.add(new BigInteger("1")))
            {
                if (e.mod(i).compareTo(new BigInteger("0"))==0)
                {
                    is_prime = false;
                    break;
                }
            }
            if (is_prime && gcd(e, phiN).compareTo(new BigInteger("1"))==0)
                break;

            e = e.add(new BigInteger("1"));
        }
        rsa_public_key public_key = new rsa_public_key(N, e);
        
        // now for the private key we use the extended euclid alg
        // such that we have 1 = s*phiN + d*e
        //linear_combination linear_comb = extended_gcd(phiN, e);
        //BigInteger d = linear_comb.t;

        //// d must be positive
        //if (d.compareTo(new BigInteger("0")) < 0)
        //    d = d.add(phiN);

        BigInteger d = RSA_private(phiN, e);

        rsa_private_key private_key = new rsa_private_key(N, d);
        return new rsa_key_pair(public_key, private_key);
    }

    // A->0, B->1,...,Z->25
    public static int char_to_value(char c)
    {
        return (int)c-65;
    }

    // inverse of char_to_value
    public static char value_to_char(int c)
    {
        return (char)(c+65);
    }

    public static BigInteger encode_msg(String msg)
    {
        BigInteger base = new BigInteger("26");
        BigInteger x = new BigInteger("0");

        for (int i = 0; i < msg.length(); ++i)
        {
            BigInteger tmp = BigInteger.valueOf((char_to_value(msg.charAt(i))));
            x = x.add(tmp.multiply(base.pow(i)));
        }
        return x;
    }

    public static String decode_msg(BigInteger encoded_msg)
    { 
        BigInteger base = new BigInteger("26");
        String msg = "";

        while (encoded_msg.compareTo(BigInteger.valueOf(0)) != 0)
        {
            // intValue should always return some integer n, so that 0 <= n <= 25
            msg = msg.concat(String.valueOf(value_to_char(encoded_msg.mod(base).intValue())));
            encoded_msg = encoded_msg.divide(base);
        }

        return msg;
    }

    // encodes and encryptes the message
    public static BigInteger rsa_encrypt(String msg, rsa_public_key pubk)
    {
        BigInteger encoded = encode_msg(msg);
        return encoded.modPow(pubk.e, pubk.N);
    }

    // decryptes and decodes the message
    public static String rsa_decrypt(BigInteger encrypted_msg, rsa_private_key privk)
    {
        BigInteger decrypted = encrypted_msg.modPow(privk.d, privk.N);
        return decode_msg(decrypted);
    }

    public static BigInteger square_and_multiply(BigInteger a, BigInteger b, BigInteger n)
    {
        BigInteger z = BigInteger.valueOf(0); 
        if (b.testBit(0))
            z = a.mod(n);
        else
            z = BigInteger.valueOf(1);

        for (int i=1; i<b.bitLength(); ++i)
        {
            a = a.pow(2);
            a = a.mod(n);
            if (b.testBit(i))
                z = z.multiply(a).mod(n);
        }
        return z;
    }

    public static void main(String[] args)
    {
        Random r = new Random();
        BigInteger p = BigInteger.probablePrime(256, r);
        BigInteger q = BigInteger.probablePrime(256, r);

        rsa_key_pair kp = construct_rsa_keypair(p,q);


        String msg = new String("DASISTEINEGEHEIMNACHRICHT");

        BigInteger encrypted = rsa_encrypt(msg, kp.pub);
        System.out.println(encrypted);

        String decrypted = rsa_decrypt(encrypted, kp.priv);
        System.out.println(decrypted);


        //BigInteger p = new BigInteger("965268402460900566905893130175198567875954976077533149965752111135677928778242951622760389058664606193897418542887204205009771546473136573124830353795329419814825468890452820118475510818402791378532378442391019678868094428194560815118667706911321381012595467778804552607276641300887525411299385909007");
        //BigInteger q = new BigInteger("494567867668539279481333488488171479757484570034435522717559423867894654782220744889038318544375933551949247273577934686988828586434497832648155459208971522506557641126436353648903769431170463197864641295604351489562632084876964472291402775145816600234597989530978896565239246792677547723194942661889");
        //rsa_key_pair kp = construct_rsa_keypair(p,q);
    }
}
