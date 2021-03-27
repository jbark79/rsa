def gcd(a,b):
    if a < b:
        tmp=a
        a=b
        b=tmp

    r = a%b
    while r!=0:
        a=b
        b=r
        r=a%b
    return b

class rsa_public_key():
    def __init__(self, N, e):
        self.N=N
        self.e=e

    def __str__(self):
        return "PUB(N={}, e={})".format(self.N, self.e)

class rsa_private_key():
    def __init__(self, N, d):
        self.N=N
        self.d=d

    def __str__(self):
        return "PRIV(N={}, d={})".format(self.N, self.d)

class rsa_key_pair():
    def __init__(self, rsa_public_key, rsa_private_key):
        self.public=rsa_public_key
        self.private=rsa_private_key

# returns a pair (s,t) s.t s*a + t*b = gcd(a,b)
def extended_gcd(a,b):
    old_r=a
    r=b
    old_s=1
    s=0
    old_t=0
    t=1

    while r!=0:
        q = old_r // r
        tmp = r 
        r = old_r - q * tmp
        old_r = tmp

        tmp = s 
        s = old_s - q * tmp
        old_s = tmp

        tmp = t 
        t = old_t - q * tmp
        old_t = tmp

    return (old_s, old_t)


def construct_rsa_keypair(p, q):

    # start with the public key
    N = p*q
    n_0 = (p-1)*(q-1)

    import math
    public_key = None

    # choose some e such that e \in P and gcd(e,n_0)=1
    e = 2
    while True:
        is_prime=True
        for i in range(2, int(math.sqrt(e))):
            if e%i == 0:
                is_prime=False
                break
        if (is_prime and gcd(e, n_0) == 1):
            public_key = rsa_public_key(N,e)
            break
        e+=1
    
    # now the private key
    # we need another value d s.t 1 = d*e - s*n_0

    # use the extended eudlic alg
    (s,t) = extended_gcd(n_0, e)
    #print("s={}, d={}".format(s,d))
    
    # d must be positive
    d=t
    if t<0:
        d+=n_0

    private_key = rsa_private_key(N, d)

    #print("p*q=N <=> {}*{}={}".format(p,q,N))
    #print("(p-1)*(q-1)=n_0 <=> {}*{}={}".format(p-1,q-1,n_0))
    #print("e = {}".format(e))
    #print("linearkombination: 1=s*n_0 + t*e <=> 1 = {} * {} + {} * {}".format(s,n_0,t,e))

    #print("d = {}".format(d))
    #print("public key: N={}, e={}".format(N,e))
    #print("private key: N={}, d={}".format(N,d))

    
    return rsa_key_pair(public_key, private_key)

def encode_msg(msg):
    x=0
    for i in range(len(msg)):
        x += char_to_num(msg[i])* 26**i
    return x

def decode_msg(encoded_msg):
    msg = ""
    while encoded_msg != 0:
        msg += num_to_char(encoded_msg % 26)
        #print(encoded_msg % 26)
        encoded_msg //= 26
    return msg

def rsa_encrypt(encoded_msg, rsa_public_key):

    #y = (encoded_msg**rsa_public_key.e) % rsa_public_key.N
    y = pow(encoded_msg, rsa_public_key.e, rsa_public_key.N)

    return y

def rsa_decrypt(encrypted, rsa_private_key):
    #x = (encrypted ** rsa_private_key.d) % rsa_private_key.N
    x = pow(encrypted, rsa_private_key.d, rsa_private_key.N)

    return x

def char_to_num(char):
    return ord(char)-65
    
    # ascii
    #return ord(char)

def num_to_char(num):
    return chr(num+65)

    # ascii
    #return chr(num)

def main():
    #p1 =965268402460900566905893130175198567875954976077533149965752111135677928778242951622760389058664606193897418542887204205009771546473136573124830353795329419814825468890452820118475510818402791378532378442391019678868094428194560815118667706911321381012595467778804552607276641300887525411299385909007 

    #q1 = 494567867668539279481333488488171479757484570034435522717559423867894654782220744889038318544375933551949247273577934686988828586434497832648155459208971522506557641126436353648903769431170463197864641295604351489562632084876964472291402775145816600234597989530978896565239246792677547723194942661889 
    #kp = construct_rsa_keypair(p1,q1)

    print("NR 36")
    pub_k = rsa_public_key(265189,3)
    print("public_key = {}".format(pub_k))
    for i in ["OK","FUN","RSA","CIAO"]:
        print("encode({:>5}) = {:<10} \t rsa_verschl({:>7}, public_key) = {}".
                format(i, encode_msg(i), encode_msg(i), rsa_encrypt(encode_msg(i), pub_k)))

    print('\n\n')

    print("NR 37")
    priv_k = rsa_private_key(221777, 176669)
    print("private_key = {}".format(priv_k))
    for i in [174259,88244,168389,218371]:
        print("rsa_entschl({:>7}, private_key) = {:<10} decode({}) -> {}".
                format(i, rsa_decrypt(i,priv_k),rsa_decrypt(i,priv_k), decode_msg(rsa_decrypt(i,priv_k))))

    print('\n\n')

    print("NR 38")
    rsa_kp = construct_rsa_keypair(89, 211)
    print("a)")
    print("public key: {}".format(rsa_kp.public))

    print("b)")
    print("private key: {}".format(rsa_kp.private))

    print("c)")
    print("rsa_entschl(4459, private_key) = {}".format(decode_msg(rsa_decrypt(4459, rsa_kp.private))))

    encoded_message = encode_msg("ILD")

    print("d)")
    print("encode(ILD) = {}".format(encoded_message))
    
    print("e)")
    alice_rsa_pubk = rsa_public_key(9617,5)
    print("rsa_verschl({}, alice_public_key) = {}".format(encoded_message, rsa_encrypt(encoded_message, alice_rsa_pubk)))


main()
