import pyDes

out_file= open("out.txt", "w")

data= "Hello there!"
k= pyDes.des("SnS!ines", pyDes.ECB, pad=None, padmode=pyDes.PAD_PKCS5)

enc_data= k.encrypt(data)
print(enc_data)
out_file.write(enc_data)
out_file.write("\n")

dec_data= k.decrypt(enc_data)
print(dec_data)
out_file.write(dec_data)
out_file.write("\n")
