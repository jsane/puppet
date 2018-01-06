require 'puppet/util/platform'

# An enum simulation to enable providing some context to encrypt/decrypt routines
# so they can use different keys 
class Puppet::Util::Artifacts
  CATALOG=1
  TRANSACTIONSTORE=2
end

class Puppet::Util::Encrypt

  def self.my_puts(str)
    # puts(str)
  end

  # Some class variables to maintain state
  # This maintains the key material to be used for encryption/decryption like key, IV
  @@km = Hash.new
  @@km_file = Puppet[:enckeymaterialfile]
  @@pkey_file = Puppet[:hostprivkey]

  # REMIND/TODO:
  # We might want to define a class and maintain the key material in class variables
  # That might avoid having to read it from file everytime after the initial generation

  # This method generates key material for a symmetric cipher and then stores them 
  # Generates new key and IV used for encrypting any sensitive artifacts maintained
  # on agent
  def self.generate_key_material()

    my_puts "Puppet::Util::Encrypt.generate_key_material invoked"
    @@km = Hash.new
  
    # AES-GCM is not supported on all ruby versions...
    cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
    @@km["catalog_key"] = cipher.random_key
    @@km["catalog_iv"] = cipher.random_iv
    @@km["catalog_encrypted"] = false

    @@km["transactstore_key"] = cipher.random_key
    @@km["transactstore_iv"] = cipher.random_iv
    @@km["transactstore_encrypted"] = false

    @@km["needs_to_be_persisted"] = true
      
    # save_key_material()
  end

  
  # Method to securely persist key materials used to encrypt sensitive artifacts
  # Parameters: 
  #  - km: Key material hash (contains keys and status flags for various artifacts)
  #  - km_file: file where to store the generated key and IV (secured using agent public key)
  #  - pkey_file: path to private key file to public encrypt the key material
  def self.save_key_material()

    my_puts "Puppet::Util::Encrypt.save_key_material invoked"

    if @@km != nil
      rsa_key = OpenSSL::PKey::RSA.new File.read(@@pkey_file)
      
      File.open(@@km_file, 'w') do |file|
        Marshal.dump(rsa_key.public_encrypt(Marshal.dump(@@km)), file)
      end
    end
  end
 

  # This method reads previously generated key material (key, IV) for a symmetric cipher
  # It would be used to decrypt previously encrypted sensitive artifacts maintained
  # on agent
  # Parameters: 
  #  - km_file: file where to read the generated key and IV from (secured using agent public key)
  #  - pkey_file: path to private key file to private decrypt the key material
  # Returns the de-constructed key material as read from the file or nil if not found
  def self.read_key_material()
  
    my_puts "Puppet::Util::Encrypt.read_key_material invoked"

    if !File.exist?(@@km_file)
      return nil
    end
  
    File.open(@@km_file, 'r') do |file|
      enc_km = Marshal.load(file)
      rsa_key = OpenSSL::PKey::RSA.new File.read(@@pkey_file)
      dec_km = rsa_key.private_decrypt(enc_km)
      @@km = Marshal.load(dec_km)
    end
    
    @@km
  end
  
  # Creates an instance of a symm cipher and returns it after priming it
  # with appropriate key, iv etc.
  # The parameter to_enc (bool) tells if it is for encryption or decryption
  # If for decryption, this will not attempt to generate a new key pair and 
  # insist on the key material to exist
  # The artifact parameter tells which key to use as we use different keys
  # since their life cycles are different.
  def self.get_cipher(to_enc, artifact)

    my_puts "Puppet::Util::Encrypt.get_cipher invoked"

    # Read key material is not already loaded...
    # if @@km == nil
      my_puts "Puppet::Util::Encrypt.get_cipher after nil check"
      km = read_key_material()
      if km.nil?
        # Let the caller deal with it instead of throwing any exception
        # There may be cases where it is ok for keys to not exist during decryption
        km = to_enc ? generate_key_material() : nil
      end
    # end
  
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    if (to_enc)
      cipher.encrypt
    else
      cipher.decrypt
    end

    my_puts 'Before setting cipher keys'
    if artifact == Puppet::Util::Artifacts::CATALOG
      cipher.key = @@km["catalog_key"]
      cipher.iv = @@km["catalog_iv"]
    elsif  artifact == Puppet::Util::Artifacts::TRANSACTIONSTORE
      cipher.key = km["transactstore_key"]
      cipher.iv = km["transactstore_iv"]
     #REMIND - do we need to handle else case if artifact is neither
    end
 
    my_puts "Puppet::Util::Encrypt.get_cipher exiting"
    cipher
  end

  # Simple method to encrypt. 
  # Takes in data to be encrypted and returns encrypted string
  def self.encrypt(to_encrypt, artifact)

    my_puts "Puppet::Util::Encrypt.encrypt invoked"
    need_to_update = false

    enc_cipher = get_cipher(true, artifact)

    # need_to_update = @@km['needs_to_be_persisted']
    need_to_update = true

    if Puppet[:secure_artifacts]
      if artifact == Puppet::Util::Artifacts::CATALOG
        # Anytime there is a state transition - from an un-encrypted artifact to encrypted one or vice versa
        # we want to update the state as it is persisted along with the keys
        if @@km["catalog_encrypted"] == false
          @@km["catalog_encrypted"] == true
          need_to_update = need_to_update || true
        end
      else
        if @@km["transactstore_encrypted"] == false
          @@km["transactstore_encrypted"] == true
          need_to_update = need_to_update || true
        end
      end 
      enc_data = enc_cipher.update(to_encrypt) + enc_cipher.final
    else
      if artifact == Puppet::Util::Artifacts::CATALOG
        if @@km["catalog_encrypted"] == true
          @@km["catalog_encrypted"] == false
          need_to_update =  need_to_update || true
        end
      else
        if @@km["transactstore_encrypted"] == true
          @@km["transactstore_encrypted"] == false
          need_to_update =  need_to_update || true
        end
      end
      enc_data = to_encrypt  # Pass thru - do not encrypt
      enc_cipher = nil  # Encryption is turned off 
    end

    if need_to_update
      save_key_material()
    end

    enc_data
  end

  # Simple method to decrypt. 
  # Takes in encrypted data string and returns decrypted string
  # 
  def self.decrypt(to_decrypt, artifact)

    # This is what we want to be able to handle (within the context of a given artifact)
    # This might be called when encryption is enabled or disabled. 
    # When disabled we want to be able to decrypt previously encrypted content if the switch to 
    # turn off encryption happened inbetween.

    dec_cipher = get_cipher(false, artifact)

    if Puppet[:secure_artifacts] && dec_cipher.nil?
      # Cannot really proceed in this case and need to throw an exception
    end

    if dec_cipher != nil
      # We base the decision to decrypt solely on the artifact_encrypted flag.
      if artifact == Puppet::Util::Artifacts::CATALOG
        plaintext = @@km["catalog_encrypted"] ? dec_cipher.update(to_decrypt) + dec_cipher.final : to_decrypt
      elsif artifact == Puppet::Util::Artifacts::TRANSACTIONSTORE
        plaintext = @@km["transactstore_encrypted"] ? dec_cipher.update(to_decrypt) + dec_cipher.final : to_decrypt
      else
        plaintext = to_decrypt  # We don't recognize why we have been called.
      end
    else
      # Ok to not have keys if "secure_artifacts" have been turned off...
      # We are taking a chance as there is minimal non-zero probability that
      # the artifact could be actually encrypted requiring keys
      if Puppet[:secure_artifacts] == false
        plaintext = to_decrypt
      end
    end

    # And we do not update key materials or state during decryption
    plaintext
  end

end
