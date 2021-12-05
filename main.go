package main

import "BTCAddressCode/address"

/**
 * @author: linfeifei
 * @email: 2778368047@qq.com
 * @phone: 18170618733
 * @DateTime: 2021/11/17 17:09
 **/
/*
生成比特币地址思路：
	1、随机生成一个私钥  命名为pri
	2、得到对应的公钥，命名为pub
	3、对公钥进行双重hash计算，得到hash原信息，
		第一重使用sha256对公钥进行hash计算，命名为pub_sha256
		第二重使用ripemd160算法对①的值进行计算，得到公钥hash值，命名为pubHash
	4、在公钥hash前面添加版本号，得到新序列，命名为ver_pubHsah
	5、对④的结果进行双重hash，取得校验位
		首先第一次sha256计算，得到结果值hash1
		然后第二次使用sha256算法对hash1进行hash计算，命名为hash2
		取hash2的前四个字节，命名为检验码check_code
	6、将检验码添加到第4步结果的最后面，得到新的序列，命名为ver_pubHsah_checkCode,意味着有三部分组成
	7、使用base58编码对第六步的结果进行编码，得到地址，命名为address
	8、反解码，逆推，看生成的比特币地址是否有效，
*/

func main() {
	address.CreateAddress()
}