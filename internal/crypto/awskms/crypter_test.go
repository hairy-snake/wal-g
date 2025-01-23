package awskms

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	mocks_awskms "github.com/wal-g/wal-g/internal/crypto/awskms/mocks"
)

func TestEncryptionCycle(t *testing.T) {
	const (
		secret = "so very secret thingy"
	)
	buf := new(bytes.Buffer)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	symmetricKey := mocks_awskms.NewMockSymmetricKey(ctrl)
	symmetricKey.EXPECT().Encrypt().Return(nil).Times(1)
	symmetricKey.EXPECT().Decrypt().Return(nil).Times(1)
	symmetricKey.EXPECT().SetKey(gomock.Any()).Times(1)
	symmetricKey.EXPECT().SetEncryptedKey(gomock.Any()).Times(1)
	symmetricKey.EXPECT().GetEncryptedKey().Return([]byte(strings.Repeat("1", 32) + strings.Repeat("0", 152))).AnyTimes()
	symmetricKey.EXPECT().GetKey().Return([]byte(strings.Repeat("2", 32))).AnyTimes()
	symmetricKey.EXPECT().GetKeyLen().Return(32).Times(1)
	symmetricKey.EXPECT().GetEncryptedKeyLen().Return(152).Times(1)

	crypter := Crypter{symmetricKey}

	encrypt, err := crypter.Encrypt(buf)
	assert.NoErrorf(t, err, "Encryption error: %v", err)

	encrypt.Write([]byte(secret))
	encrypt.Close()

	decrypt, err := crypter.Decrypt(buf)
	assert.NoErrorf(t, err, "Decryption error: %v", err)

	fmt.Println(decrypt)
	decryptedBytes, err := io.ReadAll(decrypt)
	assert.NoErrorf(t, err, "Decryption read error: %v", err)

	assert.Equal(t, secret, string(decryptedBytes), "Decrypted text not equals open text")
}
