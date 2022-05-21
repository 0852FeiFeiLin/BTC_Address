package address

import (
	"BTCAddressCode/server"
	"BTCAddressCode/util"
	"fmt"
)

/**
 * @author: linfeifei
 * @email: 2778368047@qq.com
 * @phone: 18170618733
 * @DateTime: 2021/11/17 11:34
 **/

/*
生成比特币地址思路：
	1、随机生成一个私钥  命名为pri
	2、得到对应的公钥，命名为pub
	3、对公钥进行双重hash计算，得到hash原信息，
		第一重使用sha256对公钥进行hash计算，命名为pub_sha256
		第二重使用ripemd160算法对①的值进行计算，得到公钥hash值，命名为pubHash
	4、在公钥hash前面添加版本号，得到新序列，命名为ver_pubHsah
	5、对④的结果进行双重hash，sha256算法，取得校验位
		首先第一次sha256计算，得到结果值hash1
		然后第二次使用sha256算法对hash1进行hash计算，命名为hash2
		取hash2的前四个字节，命名为检验码check_code
	6、将检验码添加到第4步结果的最后面，得到新的序列，命名为ver_pubHsah_checkCode,意味着有三部分组成
	7、使用base58编码对第六步的结果进行编码，得到地址，命名为btcAddress
	8、btcAddress反解码，得到ver_pubHash_checkCode 我们要看生成的比特币地址是否有效，就是对比检验位是否一致
		1.取出后四位检验位，命名为check1(假设是标准答案)
		2.截取除去检验位[:len(address)-4]的数据,也就是ver_pubHash，
		3.因为hash不可逆，所以，我们使用ver_pubHash进行两次hash的sha256计算，得到hash值，
     	 然后取hash值的前四作为校验码，命名为check2（待验证的答案）
		4.比较check1 是否和 check2相等,返回bool值，如果true则地址有效，反之无效。
*/

/*
	该函数用于生成比特币地址，并返回，
*/
func CreateAddress(){
	//先获取到私钥和公钥
	pri, pubBytes, err := server.CreateKeys()
	if err != nil {
		fmt.Println("生成密钥对失败",err.Error())
		return
	}
	fmt.Println("私钥：",pri)
	fmt.Printf("公钥：%x\n",pubBytes)
	fmt.Println(len(pubBytes))



	//对非压缩公钥进行双重hash计算
	pubHash := server.PubHash(pubBytes)//返回的为神么是20字节，因为ripemd160 hash计算之后就是返回20字节，160位
	fmt.Println("原始公钥哈希数据：",pubHash)
	fmt.Println(len(pubHash))

	//版本号 + 原始公钥数据 + 检验位  = 34字节
	//加上比特币地址版本号 0x00
	ver_pubHash := append([]byte{0x00},pubHash...)
	fmt.Println("版本号+原始公钥哈希：",ver_pubHash)
	fmt.Println(len(ver_pubHash))

	//ver_pubHash进行双重hash，然后取hash的前四位，然后得到检验位
	checkCode := server.CheckCode(ver_pubHash)
	fmt.Println("检验位：",checkCode)

	//ver_pubhash + 检验位
	ver_pubHash_checkCode := append(ver_pubHash,checkCode...)
	fmt.Println("还未base58的比特币地址：",ver_pubHash_checkCode)
	fmt.Println(len(ver_pubHash_checkCode))

	//然后进行base58编码，得到最后的比特币地址btcAddress
	btcAddress := util.Encode(ver_pubHash_checkCode)
	fmt.Println("btc地址：",btcAddress)
	fmt.Println("btc地址位数：",len(btcAddress))

	/*使坏，对比特币地址进行修改,然后去检验，验证输入敏感
	newAddress := strings.Replace(btcAddress, "m", "n", 1)
	isValid := server.AddressVerify(newAddress)*/

	//反解码，验证比特币地址是否有效，和之前的数据匹不匹配
	isValid := server.AddressVerify(btcAddress)

	if !isValid {
		fmt.Println("比特币地址无效: ",isValid)
		return
	}
	fmt.Println("有效!\n最终btc地址：",btcAddress)
}

