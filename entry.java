import java.math.BigInteger;

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

public class entry
{
    public static BigInteger gcd(BigInteger a, BigInteger b)
    {
        if (a.compareTo(b) < 0)
        {
            var tmp = a;
            a=b;
            b=tmp;
        }

        var r = a.mod(b);
        
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
        var old_r = a;
        var r=b;

        var old_s = new BigInteger("1");
        var s = new BigInteger("0");

        var old_t = new BigInteger("0");
        var t = new BigInteger("1");

        while (r.compareTo(new BigInteger("0")) != 0)
        {
            var q = old_r.divide(r); 
            var tmp = r;
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

    public static rsa_key_pair construct_rsa_keypair(BigInteger q, BigInteger p)
    {
        var N = p.multiply(q);
        var tmp1 = q.subtract(new BigInteger("1"));
        var tmp2 = p.subtract(new BigInteger("1"));

        var phiN = tmp1.multiply(tmp2);

        var e = new BigInteger("2");

        // find e such that e \in P and gcd(e,phiN)=1
        while (true)
        {
            var is_prime = true;
            for (var i = new BigInteger("2"); i.compareTo(e.sqrt()) < 0; i.add(new BigInteger("1")))
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

        var public_key = new rsa_public_key(N, e);
        
        // now for the private key we use the extended euclid alg
        // such that we have 1 = s*phiN - d*e, where d is a positive integer
        
        var linear_comb = extended_gcd(phiN, e);
        var d = linear_comb.t;

        // d must be positive
        if (d.compareTo(new BigInteger("0")) < 0)
            d = d.add(phiN);
        var private_key = new rsa_private_key(N, d);

        return new rsa_key_pair(public_key, private_key);
    }

    // A->1, B->2,...,Z->26
    public static int char_to_value(char c)
    {
        return (int)c-64;
    }

    // inverse of char_to_value
    public static char value_to_char(int c)
    {
        return (char)(c+64);
    }

    public static BigInteger encode_msg(String msg)
    {
        var base = new BigInteger("26");
        var x = new BigInteger("0");

        for (int i = 0; i < msg.length(); ++i)
        {
            var tmp = BigInteger.valueOf((char_to_value(msg.charAt(i))));
            x = x.add(tmp.multiply(base.pow(i)));
        }
        return x;
    }

    public static String decode_msg(BigInteger encoded_msg)
    { 
        var base = new BigInteger("26");
        String msg = "";

        while (encoded_msg.compareTo(BigInteger.valueOf(0)) != 0)
        {
            // intValue should always return some integer n, so that 1 <= n <= 26
            msg = msg.concat(String.valueOf(value_to_char(encoded_msg.mod(base).intValue())));
            encoded_msg = encoded_msg.divide(base);
        }

        return msg;
    }

    // encodes and encryptes the message
    public static BigInteger rsa_encrypt(String msg, rsa_public_key pubk)
    {
        var encoded = encode_msg(msg);
        return encoded.modPow(pubk.e, pubk.N);
    }

    // decryptes and decodes the message
    public static BigInteger rsa_decrypt(BigInteger encrypted_msg, rsa_private_key privk)
    {
        var decrypted = encrypted_msg.modPow(privk.d, privk.N);
        return decrypted;
    }

    public static void main(String[] args)
    {
        var p = new BigInteger("965268402460900566905893130175198567875954976077533149965752111135677928778242951622760389058664606193897418542887204205009771546473136573124830353795329419814825468890452820118475510818402791378532378442391019678868094428194560815118667706911321381012595467778804552607276641300887525411299385909007");

        var q = new BigInteger("494567867668539279481333488488171479757484570034435522717559423867894654782220744889038318544375933551949247273577934686988828586434497832648155459208971522506557641126436353648903769431170463197864641295604351489562632084876964472291402775145816600234597989530978896565239246792677547723194942661889");

        var keypair = construct_rsa_keypair(p,q);

        var encrypted = new BigInteger("33924201066280476046214724300018026113030797390533451217471465178938195448614240023403361319279200116541015428310732515693821362871853665256838067102914524287136546661448649117887474760902176");

        var decrypted = rsa_decrypt(encrypted, keypair.priv);
        System.out.print(decode_msg(decrypted));
    }
}
