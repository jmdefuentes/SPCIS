# Script for PRACIS mechanism for privacy-preserving and aggregatable cybesecurity information sharing
# This script focuses on message aggregation testing
# AUTHORS: Jose Maria de Fuentes (jfuentes at inf.uc3m.es), Lorena Gonzalez (lgmanzan at inf.uc3m.es)
# Version: 2016-05-01

# Contains adapted fragments of STIXProject reference implementation. For this reason the following statement applies:
# Copyright (c) 2015, The MITRE Corporation
#All rights reserved.


#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of The MITRE Corporation nor the 
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.

#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This script uses parts of LibFTE. For this reason the following statement applies:
#The MIT License (MIT)

#Copyright (c) 2016, PRACIS authors

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

# This script uses the implementation of Paillier cryptosystem of Charm-crypto, produced by J Ayo Akinyele
# Refer to charm-crypto.com for further details

#### END OF COPYRIGHT OR LICENSING NOTICES ####
# python-cybox
from cybox.common import Hash
from cybox.objects.file_object import File

# python-stix
from stix.core import STIXPackage, STIXHeader

from datetime import datetime
from cybox.common import Time

from stix.incident import Incident,ImpactAssessment, AffectedAsset
from stix.incident import Time as incidentTime # different type than common:Time

from stix.common import InformationSource
from stix.common import Confidence
from stix.common import Identity

from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.simple_marking import SimpleMarkingStructure

# libfte
import sys
import time
import random
import unittest

sys.path.append('..')
sys.path.append('../thirdparty/ffx')
sys.path.append('../thirdparty/ranking-test-framework')
import fte
# end-libfte
# libfte-stable
import fte.encoder
import fte.encrypter
import regex2dfa
#end lifte-stable

#Paillier
from charm.schemes.pkenc.pkenc_paillier99 import Pai99
from charm.schemes.pkenc.pkenc_paillier99 import Ciphertext
from charm.toolbox.integergroup import RSAGroup
from charm.toolbox.integergroup import lcm
from charm.toolbox.integergroup import integer
#end Paillier

#AES
from Crypto.Cipher import AES

#Base64
import base64

#random
import random
from random import randrange

#Hash
from hashlib import sha1
import hmac

# key = CONSUMER_SECRET& #If you dont have a token yet
key = "CONSUMER_SECRET&TOKEN_SECRET" 

ATTACK_TYPES=["DoS","Leakage","impersonation"]
pubKeyPaillier = {}
secKeyPaillier = {}
fpeKey=0
simmKey_ora_Leak = 0
simmKey_ibm_dos =0
aes_encSuite_ora = ""
aes_encSuite_ibm = ""
aes_decSuite_ora = ""
aes_decSuite_ibm = ""
pai =""
checkear=""
timer_creation_stix_FPE = 0
timer_revealing_stix_FPE =0
timer_aggregation_homo=0
timer_revealing_aggregation_homo=0
timer_setup=0
DICT_LEVEL={"High":"h","Medium":"m","Low":"l","None":"n","Unknown":"u"}
DICT_EFFECT={"Brand or Image Degradation":"Brand","Loss of Competitive Advantage":"LCAdv","Loss of Competitive Advantage - Economic":"Econo","Loss of Competitive Advantage - Military":"Milit","Data Breach or Compromise":"DataB","Degradation of Service":"Degra","Destruction":"Destr","Disruption of Service / Operations":"Disru","Financial Loss":"Finan","Loss of Confidential / Proprietary Information or Intellectual Property":"LossP","Regulatory, Compliance or Legal Impact":"RCLim","Unintended Access":"UnAcc","Loss of Competitive Advantage - Political":"Polit","User Data Loss":"UsrDL"}
DICT_TYPE={"Viruses":"virus","Worms":"worms","Trojans":"troja","Botnets":"botnt","APTs":"apert","Infostealer infections":"infst","Network scanning":"nscan","Exploitation of vulnerability":"explo","Backdoors":"backd","Brute force attacks":"brute","SQL injection attacks":"sqlin","Unauthorized elevation of privileges":"elevp","Buffer overflows":"bufov","Phising":"phisn","DoS":"deosv","DdoS":"ddosv","Jamming":"jammi","Hardware failures":"hwfai","Software failures":"swfai","Power failures":"pwfai","Network failures":"nwfai", "Unauthorised use of resources":"unres","Copyright infringement":"copyi","Miscofiguration of devices":"miscd","Abuse of privileges":"abuse","Loss/theft of devices (laptops, tablets, phones et)":"devis","Compromise of hard copy data such as loss of documents (e.g. sent via post)":"compd", "Transmission to wrong recipient (e.g. via fax).":"txerr","Flood":"flood", "Wind":"winds", "Lightening":"light","Fire":"fires","Vandalism":"vndls"} 
DICT_ASSET={"Backup":"backu","Database":"datab","DHCP":"dhcps","Directory":"direc","DNS":"dnsss","File":"files","Log":"logss","Mail":"mails","Mainframe":"mainf","Payment switch":"paysw", "POS controller":"posco","Print":"print","Proxy":"proxy","Tablet":"table","Peripheral":"perip", "POS terminal":"poste","Kiosk":"kiosk","VoIP phone":"voipp","User Device":"userd","Tapes":"tapes","Disk media":"diskm","Documents":"docum","Manager":"manag","Partner":"partn","Remote access":"remot","SCADA":"scada","Web application":"webap","Server":"serve","Access reader":"accre","Camera":"camer","Firewall":"firew","HSM":"hsmss","IDS":"idsss"}


#SETUP METHOD - Initializes all crypto parameters
def setupFPE4Cyber():
	global pai
	global pubKeyPaillier
	global secKeyPaillier
	global fpeKey
	global simmKey_ora_Leak
	global simmKey_ibm_dos
	global aes_encSuite_ora
	global aes_encSuite_ibm
	global aes_decSuite_ora
	global aes_decSuite_ibm

	# setup Paillier parameters
	group = RSAGroup()
	pai = Pai99(group)
	(pubKeyPaillier, secKeyPaillier) = pai.keygen(secparam=32)
	fpeKey = "01101001001111000011101001100101" # por ejemplo!
	# AES
	simmKey_ora_Leak = '0'*16 # por ejemplo!
	simmKey_ibm_dos = '1'*16 # por ejemplo!
	aes_encSuite_ora = AES.new(simmKey_ora_Leak, AES.MODE_CBC, 'This is an IV456')
	aes_encSuite_ibm = AES.new(simmKey_ibm_dos, AES.MODE_CBC, 'This is an IV456')
	aes_decSuite_ora = AES.new(simmKey_ora_Leak, AES.MODE_CBC, 'This is an IV456')
	aes_decSuite_ibm = AES.new(simmKey_ibm_dos, AES.MODE_CBC, 'This is an IV456')




def main():
	nA=[]
	numA=0.0
	numAAux=0.0
	numLoop=100 #aqui hay que poner n-1 siendo n el numero de mensajes a aggregar
	numA=0.0
	x=0
	for x in range(0, numLoop):
		global timer_creation_stix_FPE
		global timer_encrypt_stix
		global timer_decrypt_stix
		global timer_revealing_stix_FPE 
		global timer_aggregation_homo
		global timer_revealing_aggregation_homo
		global timer_setup
		# Setup system keys
		setupFPE4Cyber()
		global aes_encSuite_ora
		global aes_encSuite_ibm
		global fpeKey
		global checkear
		global pai


		# Prepare STIX package 1 - leakage by Oracle
		#effect1="Destruction"
		keyeffect1 = DICT_EFFECT.keys()
		ef1 = keyeffect1.index(random.choice(keyeffect1))
		#effect1 = DICT_EFFECT[keyeffect1[ef1]]
		effect1 = keyeffect1[ef1]
		keytype1 = DICT_TYPE.keys()
		ty1 = keytype1.index(random.choice(keytype1))
		type1 =  keytype1[ty1]         
		keyasset1 = DICT_ASSET.keys()
		as1 = keyasset1.index(random.choice(keyasset1))
		asset1 =  keyasset1[as1]        
		IDstix = prepareIDPaillier(45,1048575) # The incident id is prepared herein. first the length of the whole ID in bytes is provided, second random number
		IDstixEnc = encryptIDPaillier(int(IDstix))
		pkg1_type = aes_encSuite_ora.encrypt("Type leakage enterprise Oraxxx .")
		IDstix_all = base64.b64encode(str(IDstixEnc['c'])) + "-" + base64.b64encode(str(pkg1_type))
		#Prepare FPE fields
		keydiclevel1 = DICT_LEVEL.keys()
		dicL = keydiclevel1.index(random.choice(keydiclevel1))
		[confidence,restConfidence] = encryptConfidence(fpeKey,keydiclevel1[dicL])
		[effect1, restEffect1] =encryptEffect(fpeKey,effect1)
		[type1, restType1] =encryptType(fpeKey,type1)
		[asset1, restAsset1]=encryptAsset(fpeKey,asset1)
		#Create hash
		pkgcHMAC1 = IDstix_all+ confidence+restConfidence+effect1+restEffect1+type1+restType1+asset1+restAsset1
		hashed1 = hmac.new(key, pkgcHMAC1, sha1)
		hashPkg1 =hashed1.digest().encode("base64").rstrip('\n')
		pkg1 = buildSTIX(IDstix_all, confidence,restConfidence, effect1,restEffect1, type1, restType1, asset1, restAsset1,hashPkg1)
		revealSTIX(pkg1, pkg1.stix_header,restConfidence,restEffect1, restType1,restAsset1) #restXXX appear here as a workaround
		# Prepare STIX package 2 -  -------------this second package is developed to proove the aggregatePackages method
		ef2= keyeffect1.index(random.choice(keyeffect1))	
		effect2 = keyeffect1[ef2]
		ty2 = keytype1.index(random.choice(keytype1))
		type2 =  keytype1[ty2]     
		as2 = keyasset1.index(random.choice(keyasset1))
		asset2 =  keyasset1[as2]    
		IDstix2 = prepareIDPaillier(45,1048575) # The incident id is prepared herein. first the length of the whole ID in bytes is provided, second random number		
		#print("IDStix2:%s"%(IDstix))
		IDstixEnc = encryptIDPaillier(int(IDstix2))
		pkg2_type = aes_encSuite_ibm.encrypt("Type denial serv enterprise ABC.")
		IDstix_all = base64.b64encode(str(IDstixEnc['c'])) + "-" + base64.b64encode(str(pkg2_type))
		#print("IDStix2:%s: IDStixEnc2:%s:IDStixEnc2B64:%s\n"%(IDstix,IDstixEnc,base64.b64encode(str(IDstixEnc['c']))))
		#Prepare FPE fields
		dicL2 = keydiclevel1.index(random.choice(keydiclevel1))
		[confidence,restConfidence] = encryptConfidence(fpeKey,keydiclevel1[dicL2])
		[effect2, restEffect2]=encryptEffect(fpeKey,effect2)
		[type2,restType2]=encryptType(fpeKey,type2)
		[asset2,restAsset2]=encryptAsset(fpeKey,asset2)
		#Create hash
		pkgcHMAC2 = IDstix_all+ confidence+restConfidence+effect2+restEffect2+type2+restType2+asset2+restAsset2
		hashed2 = hmac.new(key, pkgcHMAC2, sha1)
		hashPkg2 =hashed2.digest().encode("base64").rstrip('\n')		
		pkg2 = buildSTIX(IDstix_all, confidence,restConfidence,effect2,restEffect2,type2,restType2,asset2,restAsset2,hashPkg2)
		revealSTIX(pkg1, pkg1.stix_header,restConfidence,restEffect1, restType1,restAsset1) #restXXX appear here as a workaround
		#Aggregate packages
		#timer_aggregation_homo=time.time()
		ttt=time.time()
		aggregatePackages(pkg1,pkg2)
		ttt2=time.time()-ttt
		#timer_aggregation_homo==time.time() - timer_aggregation_homo
		print('Time aggregation paillier EACH TIME %d' % ((x)))
		print('Time aggregation paillier EACH TIME %0.50f s' % ((numA)))
		numA+=(ttt2)
		#decrypt FPE values
		#print('Time aggregation paillier %0.5f ms' % (numAAux*1000.00))
	print('Time aggregation paillier %0.50f s' % ((numA)))

####### STIX HANDLING SECTION ########

def buildSTIX(ident,confid,restconfid, effect, resteffect,typeIncident,resttype,asset,restasset,hashPkg):
    # IMPLEMENTATION WORKAROUND - 
    # restConfid --> header.description
    # resteffect --> breach.description
    # resttype --> reporter.description
    # restasset --> reporter.identity.name 
    # setup stix document
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = restconfid # "Example description"
    stix_package.stix_header = stix_header
    # add incident and confidence
    breach = Incident(id_=ident)
    breach.description = resteffect # "Intrusion into enterprise network"
    breach.confidence = Confidence()
    breach.confidence.value=confid
    breach._binding_class.xml_type = typeIncident
    # stamp with reporter
    breach.reporter = InformationSource()
    breach.reporter.description = resttype #"The person who reported it"

    breach.reporter.time = Time()
    breach.reporter.time.produced_time = datetime.strptime("2014-03-11","%Y-%m-%d") # when they submitted it

    breach.reporter.identity = Identity()
    breach.reporter.identity.name = restasset # "Sample Investigations, LLC"

    # set incident-specific timestamps
    breach.time = incidentTime()
    breach.title = "Breach of CyberTech Dynamics"
    breach.time.initial_compromise = datetime.strptime("2012-01-30", "%Y-%m-%d") 
    breach.time.incident_discovery = datetime.strptime("2012-05-10", "%Y-%m-%d") 
    breach.time.restoration_achieved = datetime.strptime("2012-08-10", "%Y-%m-%d") 
    breach.time.incident_reported = datetime.strptime("2012-12-10", "%Y-%m-%d") 

    # add the impact
    #impact = ImpactAssessment()
    #impact.add_effect("Unintended Access")
    #breach.impact_assessment = impact
    affected_asset = AffectedAsset()
    affected_asset.description = "Database server at hr-data1.example.com" 
    affected_asset.type_ = asset
    
    breach.affected_assets = affected_asset
    #print("asset type: %s"%(breach.affected_assets[0].type_))
    # add the victim
    breach.add_victim (hashPkg)

    # add the impact
    impact = ImpactAssessment()
    impact.add_effect(effect)
    breach.impact_assessment = impact

    stix_package.add_incident(breach)
    #print("hey, I've got an incident! list size=%s"%(len(stix_package._incidents)))

    # Print the XML!
    #print(stix_package.to_xml())
    return stix_package

def revealSTIX(stix_package, stix_header,restconfidence,resteffect,resttype,restasset):
    # Goal: undo all transformations in confidence, type, effect, asset  
    # setup stix document
    breach = ""
    
    for incident in stix_package._incidents:
	breach = incident
    realConfidence = decryptConfidence('001001',str(breach.confidence.value), restconfidence)
    #print("Real confidence: %s"%(realConfidence))
    curEffect = ""
    for effect in breach.impact_assessment._effects:
	curEffect = effect
    #print("Encrypted confidence %s."%(str(curEffect)))
    realEffect = decryptEffect('001001',str(curEffect),resteffect)
    #print("Decrypted effect %s."%(str(realEffect)))
    realType = decryptType('001001',str(breach._binding_class.xml_type), resttype)
    realAsset = decryptAsset('001001', str(breach.affected_assets[0].type_), restasset)

    #print("realConfidence=%s,realEffect=%s,realType=%s,realAsset=%s"%(realConfidence, realEffect,realType,realAsset))

##### END STIX HANDLING
    



###### FORMAT-PRESERVING ENCRYPTION SECTION #######

def encryptConfidence(key, inputValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	output_raw = FPEncrypt('(h[a-zA-Z0-9_\.]+|m[a-zA-Z0-9_\.]+|u[a-zA-Z0-9_\.]+|l[a-zA-Z0-9_\.]+|n[a-zA-Z0-9_\.]+)', 32,inputValue)
	list_values = [ key for key,val in DICT_LEVEL.items() if val==output_raw[0]]
	#print("Encrypted confidence: %s"%(list_values[0]))
	return [list_values[0], output_raw[1:]]
	

def decryptConfidence(key, inputValue,restValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	real_value=DICT_LEVEL[inputValue]+restValue
	output_raw = FPDecrypt('(h[a-zA-Z0-9_\.]+|m[a-zA-Z0-9_\.]+|u[a-zA-Z0-9_\.]+|l[a-zA-Z0-9_\.]+|n[a-zA-Z0-9_\.]+)', 32,real_value)
	return output_raw

def encryptEffect(key, inputValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	output_raw = FPEncrypt('(Brand[a-zA-Z0-9_\.]+|LCAdv[a-zA-Z0-9_\.]+|Econo[a-zA-Z0-9_\.]+|Milit[a-zA-Z0-9_\.]+|Polit[a-zA-Z0-9_\.]+|DataB[a-zA-Z0-9_\.]+|Degra[a-zA-Z0-9_\.]+|Destr[a-zA-Z0-9_\.]+|Disru[a-zA-Z0-9_\.]+|Finan[a-zA-Z0-9_\.]+|LossP[a-zA-Z0-9_\.]+|RCLim[a-zA-Z0-9_\.]+|UnAcc[a-zA-Z0-9_\.]+|UsrDL[a-zA-Z0-9_\.]+)', 28,inputValue)
	list_values = [ key for key,val in DICT_EFFECT.items() if val==output_raw[0:5]]
        #print("Encrypted effect: %s,%s"%(list_values[0],output_raw))
	return [list_values[0], output_raw[5:]]

def decryptEffect(key, inputValue,restValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	real_value=DICT_EFFECT[inputValue]+restValue
        #print("Effect to decrypt %s"%(real_value))
	output_raw = FPDecrypt('(Brand[a-zA-Z0-9_\.]+|LCAdv[a-zA-Z0-9_\.]+|Econo[a-zA-Z0-9_\.]+|Milit[a-zA-Z0-9_\.]+|Polit[a-zA-Z0-9_\.]+|DataB[a-zA-Z0-9_\.]+|Degra[a-zA-Z0-9_\.]+|Destr[a-zA-Z0-9_\.]+|Disru[a-zA-Z0-9_\.]+|Finan[a-zA-Z0-9_\.]+|LossP[a-zA-Z0-9_\.]+|RCLim[a-zA-Z0-9_\.]+|UnAcc[a-zA-Z0-9_\.]+|UsrDL[a-zA-Z0-9_\.]+)', 28,real_value)
	return output_raw

def encryptType(key, inputValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	output_raw = FPEncrypt('(virus[a-zA-Z0-9_\.]+|worms[a-zA-Z0-9_\.]+|troja[a-zA-Z0-9_\.]+|botnt[a-zA-Z0-9_\.]+|apert[a-zA-Z0-9_\.]+|infst[a-zA-Z0-9_\.]+|nscan[a-zA-Z0-9_\.]+|explo[a-zA-Z0-9_\.]+|backd[a-zA-Z0-9_\.]+|brute[a-zA-Z0-9_\.]+|sqlin[a-zA-Z0-9_\.]+|elevp[a-zA-Z0-9_\.]+|bufov[a-zA-Z0-9_\.]+|phisn[a-zA-Z0-9_\.]+|deosv[a-zA-Z0-9_\.]+|ddosv[a-zA-Z0-9_\.]+|jammi[a-zA-Z0-9_\.]+|hwfai[a-zA-Z0-9_\.]+|swfai[a-zA-Z0-9_\.]+|pwfai[a-zA-Z0-9_\.]+|nwfai[a-zA-Z0-9_\.]+|unres[a-zA-Z0-9_\.]+|copyi[a-zA-Z0-9_\.]+|miscd[a-zA-Z0-9_\.]+|abuse[a-zA-Z0-9_\.]+|devis[a-zA-Z0-9_\.]+|compd[a-zA-Z0-9_\.]+|txerr[a-zA-Z0-9_\.]+|flood[a-zA-Z0-9_\.]+|winds[a-zA-Z0-9_\.]+|light[a-zA-Z0-9_\.]+|fires[a-zA-Z0-9_\.]+|vndls[a-zA-Z0-9_\.]+)', 28,inputValue)
	list_values = [ key for key,val in DICT_TYPE.items() if val==output_raw[0:5]]
	#print("Encrypted type: %s,%s, lengths: %s,%s"%(list_values[0],output_raw, len(list_values[0]),len(output_raw)))
	return [list_values[0], output_raw[5:]]

def decryptType(key, inputValue,restValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	real_value=DICT_TYPE[inputValue]+restValue
	#print("Encrypted type len: %s"%(len(real_value)))
	output_raw = FPDecrypt('(virus[a-zA-Z0-9_\.]+|worms[a-zA-Z0-9_\.]+|troja[a-zA-Z0-9_\.]+|botnt[a-zA-Z0-9_\.]+|apert[a-zA-Z0-9_\.]+|infst[a-zA-Z0-9_\.]+|nscan[a-zA-Z0-9_\.]+|explo[a-zA-Z0-9_\.]+|backd[a-zA-Z0-9_\.]+|brute[a-zA-Z0-9_\.]+|sqlin[a-zA-Z0-9_\.]+|elevp[a-zA-Z0-9_\.]+|bufov[a-zA-Z0-9_\.]+|phisn[a-zA-Z0-9_\.]+|deosv[a-zA-Z0-9_\.]+|ddosv[a-zA-Z0-9_\.]+|jammi[a-zA-Z0-9_\.]+|hwfai[a-zA-Z0-9_\.]+|swfai[a-zA-Z0-9_\.]+|pwfai[a-zA-Z0-9_\.]+|nwfai[a-zA-Z0-9_\.]+|unres[a-zA-Z0-9_\.]+|copyi[a-zA-Z0-9_\.]+|miscd[a-zA-Z0-9_\.]+|abuse[a-zA-Z0-9_\.]+|devis[a-zA-Z0-9_\.]+|compd[a-zA-Z0-9_\.]+|txerr[a-zA-Z0-9_\.]+|flood[a-zA-Z0-9_\.]+|winds[a-zA-Z0-9_\.]+|light[a-zA-Z0-9_\.]+|fires[a-zA-Z0-9_\.]+|vndls[a-zA-Z0-9_\.]+)', 28,real_value)
	return output_raw

def encryptAsset(key, inputValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	output_raw = FPEncrypt('(backu[a-zA-Z0-9_\.]+|datab[a-zA-Z0-9_\.]+|dhcps[a-zA-Z0-9_\.]+|direc[a-zA-Z0-9_\.]+|dnsss[a-zA-Z0-9_\.]+|files[a-zA-Z0-9_\.]+|logss[a-zA-Z0-9_\.]+|mails[a-zA-Z0-9_\.]+|mainf[a-zA-Z0-9_\.]+|paysw[a-zA-Z0-9_\.]+|posco[a-zA-Z0-9_\.]+|print[a-zA-Z0-9_\.]+|proxy[a-zA-Z0-9_\.]+|table[a-zA-Z0-9_\.]+|perip[a-zA-Z0-9_\.]+|poste[a-zA-Z0-9_\.]+|kiosk[a-zA-Z0-9_\.]+|voipp[a-zA-Z0-9_\.]+|userd[a-zA-Z0-9_\.]+|tapes[a-zA-Z0-9_\.]+|diskm[a-zA-Z0-9_\.]+|docum[a-zA-Z0-9_\.]+|manag[a-zA-Z0-9_\.]+|partn[a-zA-Z0-9_\.]+|remot[a-zA-Z0-9_\.]+|scada[a-zA-Z0-9_\.]+|webap[a-zA-Z0-9_\.]+|serve[a-zA-Z0-9_\.]+|accre[a-zA-Z0-9_\.]+|camer[a-zA-Z0-9_\.]+|firew[a-zA-Z0-9_\.]+|hsmss[a-zA-Z0-9_\.]+|idsss[a-zA-Z0-9_\.]+)', 32,inputValue)
	list_values = [ key for key,val in DICT_ASSET.items() if val==output_raw[0:5]]
	return [list_values[0], output_raw[5:]]	

def decryptAsset(key, inputValue, restValue):
	#TODO - key is not applied - we rely on internal keys K1 and K2 set by libfte
	real_value=DICT_ASSET[inputValue]+restValue
	output_raw = FPDecrypt('(backu[a-zA-Z0-9_\.]+|datab[a-zA-Z0-9_\.]+|dhcps[a-zA-Z0-9_\.]+|direc[a-zA-Z0-9_\.]+|dnsss[a-zA-Z0-9_\.]+|files[a-zA-Z0-9_\.]+|logss[a-zA-Z0-9_\.]+|mails[a-zA-Z0-9_\.]+|mainf[a-zA-Z0-9_\.]+|paysw[a-zA-Z0-9_\.]+|posco[a-zA-Z0-9_\.]+|print[a-zA-Z0-9_\.]+|proxy[a-zA-Z0-9_\.]+|table[a-zA-Z0-9_\.]+|perip[a-zA-Z0-9_\.]+|poste[a-zA-Z0-9_\.]+|kiosk[a-zA-Z0-9_\.]+|voipp[a-zA-Z0-9_\.]+|userd[a-zA-Z0-9_\.]+|tapes[a-zA-Z0-9_\.]+|diskm[a-zA-Z0-9_\.]+|docum[a-zA-Z0-9_\.]+|manag[a-zA-Z0-9_\.]+|partn[a-zA-Z0-9_\.]+|remot[a-zA-Z0-9_\.]+|scada[a-zA-Z0-9_\.]+|webap[a-zA-Z0-9_\.]+|serve[a-zA-Z0-9_\.]+|accre[a-zA-Z0-9_\.]+|camer[a-zA-Z0-9_\.]+|firew[a-zA-Z0-9_\.]+|hsmss[a-zA-Z0-9_\.]+|idsss[a-zA-Z0-9_\.]+)', 32,real_value)
	return output_raw


def FPEncrypt(regex, fixed_slice,input_plaintext):
	dfa = regex2dfa.regex2dfa(regex)
	fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
	cifrado = fteObj.encode(input_plaintext)
	#print("Debug: encrypting %s, result %s"%(input_plaintext,cifrado))
	#print("Debug: len(cifrado) %s"%(len(cifrado)))
	return cifrado

 
def FPDecrypt(regex, fixed_slice,cifrado): 
	dfa = regex2dfa.regex2dfa(regex)
	fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
        #print("Debug: len(cifrado) para descifrar %s"%(len(cifrado)))
	[output_plaintext, remainder] = fteObj.decode(cifrado)
	return output_plaintext

###### END FORMAT-PRESERVING ENCRYPTION SECTION #######


###### HOMOMORPHIC ENCRYPTION SECTION #######

def aggregatePackages(pkg1, pkg2):
	global pubKeyPaillier
	global secKeyPaillier
	global pai
	#global checkear
	breach1 = pkg1.incidents.pop()
	breach1_b64Paillier=breach1.id_.split('-')[0]
	breach1_Paillier=base64.b64decode(breach1_b64Paillier)
	breach2 = pkg2.incidents.pop()
	breach2_b64Paillier=breach2.id_.split('-')[0]
	breach2_Paillier=base64.b64decode(breach2_b64Paillier)
        #print("IDStixEncB64:%s: IDStixEncr1:%s\n"%(breach1_b64Paillier, breach1_Paillier))
	numeraco = breach1_Paillier.split("mod")[0]
	modulaco = breach1_Paillier.split("mod")[1]
	numeraco = int(numeraco)
	modulaco = int(modulaco)
	valoraco = pai.encode(modulaco,numeraco)
	#print("c value by encode %s\n"%(valoraco))
	numeraco2 = breach2_Paillier.split("mod")[0]
	modulaco2 = breach2_Paillier.split("mod")[1]
	numeraco2 = int(numeraco2)
	modulaco2 = int(modulaco2)
	valoraco2 = pai.encode(modulaco2,numeraco2)
	#valoraco = integer(numeraco) % integer(modulaco)
	#print("c value by mod %s\n"%(valoraco))
	# output of encrypt in Paillier --> Ciphertext({'c':c}, pk, 'c')
	aggregated = Ciphertext({'c':valoraco},pubKeyPaillier,'c') + Ciphertext({'c':valoraco2},pubKeyPaillier,'c')
	#CHECKEANDO ---
	#print(aggregated['c']==checkear['c'])
	#print(aggregated.pk == checkear.pk)
	#print(aggregated.key == checkear.key)
	#aggregated = checkear
	#FIN CHECKEANDO ---
	decrypted_msg_3 = pai.decrypt(pubKeyPaillier, secKeyPaillier, aggregated)
	#print("descifrado: %s"%(decrypted_msg_3))
	understandIDPaillier(str(decrypted_msg_3).split("mod")[0],4) # Second parameter corresponds to the filesize which has to correspond to the one used above
	#just for checking that type was OK:	
	#breach1_b64Type=breach1.id_.split('-')[1]
	#breach1_encType=base64.b64decode(breach1_b64Type)
        #breach1_type= aes_decSuite_ora.decrypt(breach1_encType)
	#print(breach1_type)

def prepareIDPaillier(lenId,random):
	bits=""
	i=0
	while(i<(lenId*8)):
		bits+="0"
		i+=1
	stringBitsRandom = bin(random)[2:]
	lenRand=len(stringBitsRandom)
	lenToReplace= len(bits)-(lenRand-2)
	bits=bits[:lenToReplace]+stringBitsRandom[2:lenRand]
	print("ID prepared %s"%(bits))
	print("ID incident LEN in bits %s"%(len(bits)))
	resultIDPaillier=int(bits,2)
	print("ID incident before encryption once converted to int %s"%(resultIDPaillier))
	return resultIDPaillier

def encryptIDPaillier(idPaillier):
    global pubKeyPaillier
    global pai
    msg_1 = pai.encode(pubKeyPaillier['n'], idPaillier)
    cipher_1 = pai.encrypt(pubKeyPaillier, msg_1)
    return cipher_1


def understandIDPaillier(receivedID, fieldSize):
	keytype2 = DICT_TYPE.keys()
	#print("Ok, received:%s"%(receivedID))
	expectedlength=fieldSize*(len(DICT_TYPE)+1)
	if(len(receivedID) != expectedlength):
		receivedID = receivedID.zfill(expectedlength+1)
	#print("Ok, received:%s"%(receivedID))
	current =0
	while(current<len(DICT_TYPE)):
		amount = int(receivedID[fieldSize*current:fieldSize*(current+1)])
		#if(amount!=0):
			#print("there are %s attacks of type %s\n"%(amount,keytype2[current]))	
		current = current +1
	
def aggregateIDs(ID1,ID2):
	return ID1+ID2

###### END HOMOMORPHIC ENCRYPTION SECTION #######

def demoPaillier():
    #DEMO PAILLIER -- suma!!
    group = RSAGroup()
    pai = Pai99(group)
    (pubKeyPaillier, secKeyPaillier) = pai.keygen()
    msg_1=12345678987654321
    msg_2=12345761234123409
    msg_3 = msg_1 + msg_2
    print("msg1:%s\n,msg2:%s\n,msg3:%s\n"%(msg_1,msg_2,msg_3))
    msg_1 = pai.encode(pubKeyPaillier['n'], msg_1)
    msg_2 = pai.encode(pubKeyPaillier['n'], msg_2)
    msg_3 = pai.encode(pubKeyPaillier['n'], msg_3)
    print("msg1:%s\n,msg2:%s\n,msg3:%s\n"%(msg_1,msg_2,msg_3))
    cipher_1 = pai.encrypt(pubKeyPaillier, msg_1)
    cipher_2 = pai.encrypt(pubKeyPaillier, msg_2)
    print("ciph1:%s\n,ciph2:%s\n"%(cipher_1['c'],cipher_2['c']))
    cipher_3 = cipher_1 #+ cipher_2
    print("ciph3:%s\n"%(cipher_3))
    #wtf_3 = ((cipher_1['c'] % pubKeyPaillier['n'])  * (cipher_2['c'] % pubKeyPaillier['n'],2) ) % pubKeyPaillier['n']
    decrypted_msg_3 = pai.decrypt(pubKeyPaillier, secKeyPaillier, cipher_3)
    print(decrypted_msg_3)
    bool=decrypted_msg_3 == msg_3
    print(bool)
    #print("decrypted_msg3:%s\n,wtf_3:%s\n"%(decrypted_msg_3,wtf_3))
    #bool2=decrypted_msg_3 == wtf_3
    #print(bool2)
#DEMO FPE

def demoFPE():
    input_format = ('([a-z0-9_\.]+)@([0-9a-z\.]+)\.([a-z\.]{2,6})', 32)
    output_format = ('(https?:\/\/)([\da-z\.\-]+)\.([a-z\.]{2,6})([\/\w \.\-]*)*\/?', 64)
    K = '1' * 32
    fpe = FTE.new(K, input_format=input_format, output_format=output_format)
    #N = random.randint(0, fpe._input_ranker.getNumWordsInLanguage() - 1)
    #X = fpe._input_ranker.unrank(N)
    X = "dmdmasymastellmeblablahs@uc3m.es"
    C = fpe.encrypt(X)
    Y = fpe.decrypt(C)

    #print 'input_format=' + str(input_format)
    #print 'output_format=' + str(output_format)
    print 'plaintext=' + X
    print 'ciphertext=' + C
    print 'decrypted=' +Y

# DEMO AES Decryption
    #plain_text = decryption_suite.decrypt(cipher_text)
if __name__ == '__main__':
    main()
