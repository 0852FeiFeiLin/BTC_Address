package server

import (
	"BTCAddressCode/util"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

/**
 * @author: linfeifei
 * @email: 2778368047@qq.com
 * @phone: 18170618733
 * @DateTime: 2021/11/17 11:34
 **/

/*
	生成密钥对：并返回
*/
func CreateKeys() (*ecdsa.PrivateKey, []byte, error) {
	//曲线方程
	curve := elliptic.P256()
	//生成私钥
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	//公钥 = x + y
	pub := privateKey.PublicKey
	/*
		//x 和 y 坐标组成公钥
		x := pub.X
		y := pub.Y
		//传统拼接publicKey := append(pub.X.Bytes(),pub.Y.Bytes()...)
		//高级拼接	publicKey := elliptic.Marshal(curve, pub.X, pub.Y)
	*/

	//拼接公钥  传统方式append ，高级方式marshal
	//x 和 y 坐标拼接组成64字节公钥,加上前面标志位1字节 = 65字节
	publicKey := elliptic.Marshal(curve, pub.X, pub.Y)  //得到非压缩公钥
	/*
		//没进行压缩的公钥，64字节，称之为非压缩公钥。
		//公钥进行压缩，称之为压缩公钥
			最后公钥还是64字节，还是太长了，
			所以进行压缩，得到压缩公钥

			非压缩公钥前面加上标志位，就是65字节，所以说实际公钥长度是65字节


		非压缩 公钥格式（原始公钥）：标志位(1个字节)+公钥原始数据(64个字节)
		压缩 公钥格式： 标志位  + 公钥x坐标 (33字节)
	*/
	//压缩公钥
	//pubKey := CatDownPubKey(pub)
	//返回私钥和原始公钥
	return privateKey,publicKey, nil
}

/*
	返回压缩公钥的字节切片
*/
func CatDownPubKey(publicKey ecdsa.PublicKey) []byte {
	var pub []byte
	b := big.NewInt(0)
	//判断y坐标，
	if publicKey.Y.Cmp(b) == -1 { //y < 0 ==> 02
		xByte := publicKey.X.Bytes()
		pub = append([]byte{02}, xByte...) //压缩公钥
	} else { //y > 0 ==> 03
		xByte := publicKey.X.Bytes()
		pub = append([]byte{03}, xByte...) //压缩公钥
	}
	return pub
}

//交易序列化方法
/*func  Serialize() ([]byte, error) {
	var result bytes.Buffer

	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(txs)
	if err != nil {
		return nil, err
	}
	//返回序列化结果
	return result.Bytes(), nil
}*/

/*
	该函数用于将公钥进行双重hash，返回公钥hash
*/
func PubHash(pub []byte) []byte {
	//第一重加密 ： sha256加密
	hash := util.SHA256Hash(pub)
	//第二重加密 ： ripemd加密
	ripemd := ripemd160.New()
	ripemd.Write(hash)
	pubHash := ripemd.Sum(nil)
	return pubHash //ripemd返回的是160位，也就是20字节

}

/*
	该函数用于将ver_pubHash进行双重hash运算，取hash值的前四位，得到校验位,并返回
*/
func CheckCode(ver_pubHash []byte) []byte {
	hash1 := util.SHA256Hash(ver_pubHash)
	hash2 := util.SHA256Hash(hash1)
	//取hash2的四字节作为检验码
	checkCode := hash2[:4]
	//前四个字节  []byte:4位  hex：十六进制：8位
	return checkCode
}

/*
	该函数用于反解码，验证比特币地址是否有效，就是验证校验码，
	如果check1 == check2，
	返回true，代表地址有效，反之false，地址无效。
*/
func AddressVerify(btcAddress string) bool {
	if btcAddress == "" { //如果是空字符串
		return false
	}
	//base58反解码
	address := util.Decode(btcAddress)
	// 得到 ver_pubHash_checkCode 三部分

	//然后截取后四字节，得到检验码(标准答案)
	check1 := address[len(address)-4:]
	/*
		为神么不使用最后的btcAdress反解码后，再进行逆推反hahs解码，
		因为hash计算是不可逆的，
		所以只能截取前面部分来进行再次双重hash计算，得到检验码，然后比较两个的校验码是否一致，
		一致代表地址有效
	*/
	//然后获取前面部分进行两次hash计算，sha256
	ver_pubHash := address[0 : len(address)-4]
	//双重hash计算sha256算法，取hash值的前四位作为校验码
	hash1 := util.SHA256Hash(ver_pubHash)
	hash2 := util.SHA256Hash(hash1)

	//hash值的前四位，得到校验码
	check2 := hash2[:4]

	//返回比较的结果 []byte类型比较
	//return bytes.Equal(check1,check2) //判断值是否相等

	return bytes.Compare(check1, check2) == 0 //比较值然后比较值的长度，相等返回0，a>b 返回1，a<b 返回-1
}
