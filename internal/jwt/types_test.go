package jwt

// TODO: Implement this to ensure the different broken cases will be caught (missing env vars, no files at expected locations, ...)
//func TestNewTokenIssuer(t *testing.T) {
//	tests := []struct {
//		name    string
//		want    *TokenIssuer
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := NewTokenIssuer()
//			if (err != nil) != tt.wantErr {
//				t.Errorf("NewTokenIssuer() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if !reflect.DeepEqual(got, tt.want) {
//				t.Errorf("NewTokenIssuer() got = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}
