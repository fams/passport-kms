// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/matelang/jwt-go-aws-kms/v2/jwtkms (interfaces: KMSClient)
//
// Generated by this command:
//
//	mockgen -destination=mocks/mock_jwtkmsclient.go -package=mocks github.com/matelang/jwt-go-aws-kms/v2/jwtkms KMSClient
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	gomock "go.uber.org/mock/gomock"
)

// MockKMSClient is a mock of KMSClient interface.
type MockKMSClient struct {
	ctrl     *gomock.Controller
	recorder *MockKMSClientMockRecorder
	isgomock struct{}
}

// MockKMSClientMockRecorder is the mock recorder for MockKMSClient.
type MockKMSClientMockRecorder struct {
	mock *MockKMSClient
}

// NewMockKMSClient creates a new mock instance.
func NewMockKMSClient(ctrl *gomock.Controller) *MockKMSClient {
	mock := &MockKMSClient{ctrl: ctrl}
	mock.recorder = &MockKMSClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKMSClient) EXPECT() *MockKMSClientMockRecorder {
	return m.recorder
}

// GetPublicKey mocks base method.
func (m *MockKMSClient) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, in}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetPublicKey", varargs...)
	ret0, _ := ret[0].(*kms.GetPublicKeyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKey indicates an expected call of GetPublicKey.
func (mr *MockKMSClientMockRecorder) GetPublicKey(ctx, in any, optFns ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, in}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKey", reflect.TypeOf((*MockKMSClient)(nil).GetPublicKey), varargs...)
}

// Sign mocks base method.
func (m *MockKMSClient) Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, in}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Sign", varargs...)
	ret0, _ := ret[0].(*kms.SignOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockKMSClientMockRecorder) Sign(ctx, in any, optFns ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, in}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockKMSClient)(nil).Sign), varargs...)
}

// Verify mocks base method.
func (m *MockKMSClient) Verify(ctx context.Context, in *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []any{ctx, in}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Verify", varargs...)
	ret0, _ := ret[0].(*kms.VerifyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockKMSClientMockRecorder) Verify(ctx, in any, optFns ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx, in}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockKMSClient)(nil).Verify), varargs...)
}
