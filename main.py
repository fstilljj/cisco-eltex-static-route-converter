import netmiko
from os.path import isfile
from sys import exit
from dotenv import dotenv_values as env

def read_file(file:str):
    if not isfile(file): return False

    with open(file, "r") as file:
        result = [x for x in file.read().split("\n") if x]

    return result


def parsing(cisco_acl:str, name_ac:str):
    for count, i in enumerate(cisco_acl, 1):
    	if i.split(' ')[1] == 'permit':
    		act = 'action permit'
    		if i.split(' ')[3] == 'host':
    			so_ad_msk = '255.255.255.255'
    			so_ad = i.split(' ')[4]
    			if i.split(' ')[5] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad_a_msk}', 'ma pro an', 'enable'] 
    			elif i.split(' ')[5] == 'host':
    				d_msk = '255.255.255.255'
    				d_ad = i.split(' ')[6]
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    			else:
    				d_ad = i.split(' ')[5]
    				d_msk = []
    				for bits in i.split(' ')[6].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    		elif i.split(' ')[3] == 'any':
    			so_ad_a_msk = 'any'
    			if i.split(' ')[4] == 'host':
    				d_msk = '255.255.255.255'
    				d_ad = i.split(' ')[5]
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    			elif i.split(' ')[4] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destiantion-a {d_ad_a_msk}', 'ma pro an', 'enable'] 
    			else:
    				d_ad = i.split(' ')[4]
    				d_msk = []
    				for bits in i.split(' ')[5].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    		else:
    			so_ad = i.split(' ')[3]
    			so_ad_msk = i.split(' ')[4]
    			if i.split(' ')[5] == 'host':
    				d_msk = '255.255.255.255'
    				d_ad = i.split(' ')[6]
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    			elif i.split(' ')[5] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad_a_msk}', 'ma pro an', 'enable'] 
    			else:
    				d_msk = []
    				for bits in i.split(' ')[6].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				d_ad = i.split(' ')[5]
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable'] 
    	elif i.split(' ')[1] == 'deny':
    		act = 'action deny'
    		if i.split(' ')[5] == 'host':
    			so_ad = i.split(' ')[6]
    			so_ad_msk = '255.255.255.255'
    			if i.split(' ')[7] == 'host':
    				d_ad = i.split(' ')[8]
    				d_msk = '255.255.255.255'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
    			elif i.split(' ')[7] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad_a_msk}', 'ma pro an', 'enable']
    			else:
    				d_ad = i.split(' ')[7]
    				d_msk = []
    				for bits in i.split(' ')[8].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
    		elif i.split(' ')[5] == 'any':
    			so_ad_a_msk = 'any'
    			if i.split(' ')[6] == 'host':
    				d_ad = i.split(' ')[7]
    				d_msk = '255.255.255.255'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
    			elif i.split(' ')[6] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destination-a {d_ad_a_msk}', 'ma pro an', 'enable']
    			else:
    				d_ad = i.split(' ')[6]
    				d_msk = []
    				for bits in i.split(' ')[7].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad_a_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
    		else:
    			so_ad = i.split(' ')[5]
    			so_ad_msk = i.split(' ')[6]
    			if i.split(' ')[7] == 'host':
    				d_ad = i.split(' ')[8]
    				d_msk = '255.255.255.255'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
    			elif i.split(' ')[7] == 'any':
    				d_ad_a_msk = 'any'
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad_a_msk}', 'ma pro an', 'enable']
    			else:
    				d_ad = i.split(' ')[7]
    				d_msk = []
    				for bits in i.split(' ')[8].split('.'):
    					d_msk.append(str(255 - int(bits)))
    				d_msk = '.'.join(d_msk)
    				al = [f'ip ac ex {name_ac}', f'rule {count}', act, f'ma source-a {so_ad} {so_ad_msk}', f'ma destination-a {d_ad} {d_msk}', 'ma pro an', 'enable']
        yield al


def main():
    credits = {
        "device_type": "eltex",
        "host": env(".env")["host"],
        "username": env(".env")["username"],
        "password": env(".env")["password"],
        "secret": env(".env")["secret"],
        "port": 22
    }
    filename = "asdasad"
    
    if not read_file(filename):
        print(f"File '{filename}' not found\nExiting...")
        exit(1)

    
        


if __name__=="__main__":
    main()
