require 'puppet/util/platform'

module Puppet::Util::Encrypt


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
  
    cipher = OpenSSL::Cipher.new('AES-256-CBC').encrypt
    key_material['key'] = cipher.random_key
    key_material['iv'] = cipher.random_iv

    # TODO:: Compute a hash checksum on the key material
  
    # If/when decide to support AES GCM we would need to supply auth_data and store auth_tag. 
    # It is not supported in all ruby versions
    
    rsa_key = OpenSSL::PKey::RSA.new File.read(pkey_file)
    
    File.open(km_file, 'w') do |file|
      Marshal.dump(rsa_key.public_encrypt(Marshal.dump(key_material)), file)
    end
  
    key_material
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
  
  def get_cipher(to_enc)
    km_file = Puppet[:enckeymaterialfile]
    km = read_key_material(km_file, Puppet[:hostprivkey])
    if km.nil?
      if to_enc
        km = generate_key_material(km_file, Puppet[:hostprivkey])
      else
        return nil
      end
    end
  
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    if (to_enc)
      cipher.encrypt
    else
      cipher.decrypt
    end
    cipher.key = km['key']
    cipher.iv = km['iv']
  
    cipher  
  end

  # Simple method to encrypt. 
  # Takes in data to be encrypted and returns encrypted string
  
  def encrypt(to_encrypt)

    # TODO::
    # Whether to encrypt or not would be controlled by a configuration switch 
    # secure_artifacts
    enc_cipher = get_cipher(true)

    if enc_cipher
      enc_data = enc_cipher.update(to_encrypt) + enc_cipher.final
    else
      enc_data = nil
      # REMIND: We may need to throw an exception if we are unable to encrypt
    end

    enc_data
  end

  # Simple method to decrypt. 
  # Takes in encrypted data string and returns decrypted string
  # 
  def decrypt(to_decrypt)

    # TODO::
    # Whether to decrypt or not would be controlled by a configuration switch 
    # secure_artifacts
    # Need to handle the case where the relevant artifacts might be encrypted in file
    # then encryption gets disabled. During decryption in such cases it needs to know
    # the artifact is encrypted that should be decrypted and returned.
    # It might be best left to the caller to do that checking since this method lacks
    # context 

    dec_cipher = get_cipher(false)
    if dec_cipher
      plaintext = dec_cipher.update(to_decrypt) + dec_cipher.final
    else
      # REMIND: We may need to throw an exception if we are unable to decrypt
      plaintext = nil
    end

    plaintext
  end

end
