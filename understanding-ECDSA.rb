require 'ecdsa'
require 'securerandom'
require 'base64'


$group = ECDSA::Group::Secp256k1
#$private_key = 46851821956481904104016230522661634505981924851921687582944938792993143911960
# hex 67953105b80ce1a2b51614c820b2167e87b8cee8d191e2844e86c2feb177f618

$private_key = 94315645564886237271418458311381220199248805283311829997486022545480283028259
# hex = d084c37e5a726c88af2438342d2886a24c615c415b40343c57f3ca9171877b23

#$private_key = 26352885302424468405266659557974868558217370049170189840845555947322106925591
$public_key = $group.generator.multiply_by_scalar($private_key)
$temp_key = 5 # this is 'k', this should never be static! (isnt that right sony?!! https://www.youtube.com/watch?v=-UcCMjQab4w)

#using an array here, to extract the privat key it required 2 messages, and signatures, its easier to keep track of if we index them. (message 1 [0] is for signature 1 [0])
$signature_array = Array.new
$digest_array = Array.new



#str is the data that will be signed (digest)
def createsignature(str)
    signature_raw = sign(str)
    signature_der = ECDSA::Format::SignatureDerString.encode(signature_raw)
    signature_der_b64 = Base64.strict_encode64(signature_der) 
    digest_raw = Digest::SHA256.digest(str)
    digest_b64 = Base64.encode64(digest_raw)
    #Base64 encoding was used due to the readablility, and transportability.    
    puts("Signature (b64 encoded der): "+signature_der_b64)
    puts("Digest (b64 endoded): "+digest_b64)
    $signature_array.push(signature_der_b64)
    $digest_array.push(digest_b64)
    #return signature_der_b64
end


def recover_publickey(signature, digest)
    #required to normalize back to its native raw format
    signature_der = Base64.decode64(signature)
    signature_raw = ECDSA::Format::SignatureDerString.decode(signature_der)
    digest_raw = Base64.decode64(digest)

    #enumerator object, shows multiple arrays that are possible public keys (there can be multiple public keys for a single private key)
    recoveredpubkeys_enum = ECDSA.recover_public_key($group, digest_raw, signature_raw) 
    recoveredpubkeys_array = recoveredpubkeys_enum.to_a #converts enum object to an array

    #shows the enum object, and its 
    puts("Enum Object: "+recoveredpubkeys_enum.inspect.to_s()) 

    #shows multiple possible public keys (points). [0] public key 1, [1] public key 2 ect.
    #puts(recoveredpubkeys_array.inspect)   

    puts("Recovered ECDSA Point (Public Key): "+recoveredpubkeys_array[0].inspect.to_s()) # returns the first ECDSA point object, this contains the group (Secp256k1), and the x and y co-ordinants on the public key
    valid = ECDSA.valid_signature?(recoveredpubkeys_array[0], digest_raw, signature_raw) #should return true, proves that the recovered public key  us currect
    #puts(valid)
end




#Recover private key code from here: https://bitcoin.stackexchange.com/questions/35848/recovering-private-key-when-someone-uses-the-same-k-twice-in-ecdsa-signatures/35850#35850
def recover_priv(msg1, msg2, sig1_b64, sig2_b64)
    #WIP!
    public_key = recoverpub_b64(msg1, sig1_b64)
    public_key2 = recoverpub_b64(msg2, sig2_b64)

    msghash1 = Base64.decode64(msg1)
    msghash2 = Base64.decode64(msg2)
    sig1 = ECDSA::Format::SignatureDerString.decode(Base64.decode64(sig1_b64))
    sig2 = ECDSA::Format::SignatureDerString.decode(Base64.decode64(sig2_b64))

    puts 'public key x: %#x' % public_key.x
    puts 'public key y: %#x' % public_key.y

    raise 'R values are not the same' if sig1.r != sig2.r
  
    r1 = sig1.r
    r2 = sig2.r
  
    r = sig1.r
    #puts 'sig1 r: '+r1.to_s()
    #puts 'sig2 r: '+r2.to_s()
    #puts 'sig1 s: '+sig1.s.to_s()
    #puts 'sig2 s: '+sig2.s.to_s()
    puts 'r = %#x' % r1
    puts 's1 = %#x' % sig1.s
    puts 's2 = %#x' % sig2.s
  
    # Step 1: k = (z1 - z2)/(s1 - s2)
    field = ECDSA::PrimeField.new($group.order)
    z1 = ECDSA::Format::IntegerOctetString.decode(msghash1)
    puts 'z1 = %#x' % z1
    puts(Base64.strict_encode64(msghash1))
    z2 = ECDSA::Format::IntegerOctetString.decode(msghash2)
    puts 'z2 = %#x' % z2
    puts(Base64.strict_encode64(msghash2))
    k_candidates = [
      field.mod((z1 - z2) * field.inverse(sig1.s - sig2.s)),
      field.mod((z1 - z2) * field.inverse(sig1.s + sig2.s)),
      field.mod((z1 - z2) * field.inverse(-sig1.s - sig2.s)),
      field.mod((z1 - z2) * field.inverse(-sig1.s + sig2.s)),
    ]
  
    private_key = nil
    k_candidates.each do |k|
      next unless $group.new_point(k).x == r
      private_key_maybe = field.mod(field.mod(sig1.s * k - z1) * field.inverse(r))
      if public_key == $group.new_point(private_key_maybe)
        private_key = private_key_maybe
      end
    end
    print("Privatekey:")
    puts (private_key)
    puts 'Private Key: %#x' % private_key
    puts
  end

  def recoverpub_b64(str, sig)
    digest = Base64.decode64(str)
    sig = ECDSA::Format::SignatureDerString.decode(Base64.decode64(sig))
    
    recoveredpubkeys = ECDSA.recover_public_key($group, digest, sig)
    rpk_array = recoveredpubkeys.to_a

    puts(recoveredpubkeys.inspect)
    puts(rpk_array[0])
    return rpk_array[0]
end

def sign(str)
    digest = Digest::SHA256.digest(str) 
    temp_key = str.size #Insecure, *NEVER* use a static/non-random temporary key (k)
    signature = ECDSA.sign($group, $private_key, digest, temp_key)
end

def verify?(pk, str, signature)
    digest = Digest::SHA256.digest(str)
    ECDSA.valid_signature?(pk, digest, signature)
end


createsignature('test')
recover_publickey($signature_array[0], $digest_array[0])
