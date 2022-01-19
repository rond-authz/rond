package main

import (
	"net/http"
)

type OpaResponseWriter struct {
	ResponseDefaultWriter http.ResponseWriter
}

func NewOpaResponseWriter(w http.ResponseWriter) http.ResponseWriter {
	return &OpaResponseWriter{ResponseDefaultWriter: w}
}

func (w *OpaResponseWriter) Write(b []byte) (int, error) {
	result, err := w.ResponseDefaultWriter.Write(b)
	return result, err
}

func (w *OpaResponseWriter) Header() http.Header {
	return w.ResponseDefaultWriter.Header()
}

func (w *OpaResponseWriter) WriteHeader(statusCode int) {
	w.ResponseDefaultWriter.WriteHeader(statusCode)
}
