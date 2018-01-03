require 'puppet/util/platform'

module Puppet::Util::Encrypt


  # An enum simulation to enable providing some context to encrypt/decrypt routines
  # so they can use different keys 
  class Artifacts
    CATALOG=1
    TRANSACTIONSTORE=2
  end

  # REMIND/TODO:
  # We might want to define a class and maintain the key material in class variables
  # That might avoid having to read it from file everytime after the initial generation

  # This method generates key material for a symmetric cipher and then stores them 
  # Generates new key and IV used for encrypting any sensitive artifacts maintained
  # on agent
  # Parameters: 
  #  - km_file: file where to store the generated key and IV (secured using agent public key)
  #  - pkey_file: path to private key file to public encrypt the key material
  def generate_key_material(km_file, pkey_file)
  
    key_material = Hash.new
  
    # In case encryption is disabled then set all keys and ivs to nil
    if Puppet[:secure_artifacts] == true
      cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
      key_material['catalog_key'] = cipher.random_key
      key_material['catalog_iv'] = cipher.random_iv
      key_material['transactstore_key'] = cipher.random_key
      key_material['transactstore_iv'] = cipher.random_iv
    else
      key_material['catalog_key'] = nil
      key_material['catalog_iv'] =  nil
      key_material['transactstore_key'] =  nil
      key_material['transactstore_iv'] =  nil
    end

    # TODO:: Compute a hash checksum on the key material
  
    # If/when decide to support AES GCM we would need to supply auth_data and store auth_tag. 
    # It is not supported in all ruby versions
    
    rsa_key = OpenSSL::PKey::RSA.new File.read(pkey_file)
    
    File.open(km_file, 'w') do |file|
      Marshal.dump(rsa_key.public_encrypt(Marshal.dump(key_material)), file)
    end
  
    key_material
  end
 
  # This method generates key material for a symmetric cipher and then stores them 
  # Generates new key and IV used for encrypting any sensitive artifacts maintained
  # on agent
  # Parameters: 
  #  - km_file: file where to store the generated key and IV (secured using agent public key)
  #  - pkey_file: path to private key file to public encrypt the key material
  #  - artifact: keys for what like catalog, transaction store 
  #  - delete: are the keys to be deleted or generated. 

  def update_key_material(km_file, pkey_file, artifact, delete)
  
    update_km_file = false

    km = read_key_material(km_file, pkey_file)
    if km == nil
      km = Hash.new  # in the remote possibility this happens
    end
  
    if artifact == Artifacts::CATALOG
      if delete
        update_km_file = km['catalog_key'] != nil
        km['catalog_key'] = nil
        km['catalog_iv'] = nil
      else
        update_km_file = km['catalog_key'] == nil
        cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
        km['catalog_key'] = cipher.random_key
        km['catalog_iv'] = cipher.random_iv
      end
    elsif artifact == Artifacts::TRANSACTIONSTORE
      if delete
        update_km_file = km['transactstore_key'] != nil
        km['transactstore_key'] = nil
        km['transactstore_iv'] = nil
      else
        update_km_file = km['transactstore_key'] == nil
        cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
        km['transactstore_key'] = cipher.random_key
        km['transactstore_iv'] = cipher.random_iv
      end
    end

    # Update the key materials only when needed 
    if update_km_file
      rsa_key = OpenSSL::PKey::RSA.new File.read(pkey_file)
      
      File.open(km_file, 'w') do |file|
        Marshal.dump(rsa_key.public_encrypt(Marshal.dump(key_material)), file)
      end
    end
  
    km
  end

  # This method reads previously generated key material (key, IV) for a symmetric cipher
  # It would be used to decrypt previously encrypted sensitive artifacts maintained
  # on agent
  # Parameters: 
  #  - km_file: file where to read the generated key and IV from (secured using agent public key)
  #  - pkey_file: path to private key file to private decrypt the key material
  def read_key_material(km_file, pkey_file)
  
    if !File.exist?(km_file)
      return nil
    end
  
    key_material = nil
    File.open(km_file, 'r') do |file|
      enc_km = Marshal.load(file)
      rsa_key = OpenSSL::PKey::RSA.new File.read(pkey_file)
      dec_km = rsa_key.private_decrypt(enc_km)
      key_material = Marshal.load(dec_km)
    end
    
    key_material
  end
  
  # Creates an instance of a symm cipher and returns it after priming it
  # with appropriate key, iv etc.
  # The parameter to_enc (bool) tells if it is for encryption or decryption
  # If for decryption, this will not attempt to generate a new key pair and 
  # insist on the key material to exist
  # The artifact parameter tells which key to use as we use different keys
  # since their life cycles are different.
  
  def get_cipher(to_enc, artifact)
    km_file = Puppet[:enckeymaterialfile]
    km = read_key_material(km_file, Puppet[:hostprivkey])
    if km.nil?
      km = to_enc == true ? generate_key_material(km_file, Puppet[:hostprivkey]) : nil
    end
  
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    if (to_enc)
      cipher.encrypt
    else
      cipher.decrypt
    end
    if artifact == Artifacts::CATALOG
      cipher.key = km['catalog_key']
      cipher.iv = km['catalog_iv']
    elsif  artifact == Artifacts::TRANSACTIONSTORE
      cipher.key = km['transactstore_key']
      cipher.iv = km['transactstore_key']
     #REMIND - do we need to handle else case if artifact is neither
    end
 
    cipher  
  end

  # Simple method to encrypt. 
  # Takes in data to be encrypted and returns encrypted string
  
  def encrypt(to_encrypt, artifact)

    # TODO::
    # Whether to encrypt or not would be controlled by a configuration switch 
    # secure_artifacts
    enc_cipher = get_cipher(true, artifact)
    enc_data = enc_cipher != nil ? enc_cipher.update(to_encrypt) + enc_cipher.final : to_encrypt

    enc_data


    # TODO:
    # This is what we want to be able to handle (within the context of a given artifact)
    # This might be called when encryption is enabled or disabled. 
    # When disabled we want to remove the keys if they were still valid
    # When enabled and if the keys do not exist then create them. 
    # In either case if there has been a key transition then they need to be saved.
  end

  # Simple method to decrypt. 
  # Takes in encrypted data string and returns decrypted string
  # 
  def decrypt(to_decrypt, artifact)

    # TODO:
    # This is what we want to be able to handle (within the context of a given artifact)
    # This might be called when encryption is enabled or disabled. 
    # When disabled we want to be able to decrypt previously encrypted content if the switch to 
    # turn off encryption happened inbetween.  In such cases we need to remove the keys if they were still valid
    # after we do the encryption.
    # If there has been a key transition then they need to be saved.
    # Needs to be seen if it might be best left to the caller to do that checking

    dec_cipher = get_cipher(false, artifact)
    plaintext = dec_cipher != nil ? dec_cipher.update(to_decrypt) + dec_cipher.final : to_decrypt

    plaintext
  end

end
