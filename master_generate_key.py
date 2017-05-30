import Crypto.PublicKey.RSA as RSA
import os
import os.path

def confirm_overwrite():
	overwrite = input("Overwrite key (y or n)? ")
	if overwrite == "y":
		return True
	elif overwrite == "n":
		return False
	else:
		return confirm_overwrite()

def generate_key(fn):
	keys = RSA.generate(2048)
	private = open(fn,'w')
	private.write(keys.exportKey("PEM").decode("utf-8"))
	private.close()

	public = open(fn + ".pub",'w')
	public.write(keys.publickey().exportKey("PEM").decode("utf-8"))
	public.close()

if __name__ == "__main__":
	fn = input("File Name: ")
	if os.path.isfile(fn):
		if confirm_overwrite():
			generate_key(fn)
	else:
		generate_key(fn)