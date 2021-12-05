package util

import "crypto/sha256"

/**
 * @author: linfeifei
 * @email: 2778368047@qq.com
 * @phone: 18170618733
 * @DateTime: 2021/11/17 19:06
 **/
func SHA256Hash(data []byte)([]byte){
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(data)
}