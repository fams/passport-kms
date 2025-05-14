package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"io"
	"lambda-ca-kms/handlers"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp, _ := handlers.HandleSignCSR(context.Background(), wrapRequest(string(body)))
		w.WriteHeader(resp.StatusCode)
		fmt.Fprint(w, resp.Body)
	})

	http.HandleFunc("/sign-jwt", func(w http.ResponseWriter, r *http.Request) {
		resp, _ := handlers.HandleSignJWT(context.Background(), wrapRequest(""))
		w.WriteHeader(resp.StatusCode)
		fmt.Fprint(w, resp.Body)
	})

	http.HandleFunc("/public-key", func(w http.ResponseWriter, r *http.Request) {
		resp, _ := handlers.HandleGetPublicKey(context.Background(), wrapRequest(""))
		w.WriteHeader(resp.StatusCode)
		fmt.Fprint(w, resp.Body)
	})

	log.Println("Servidor local ouvindo em http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func wrapRequest(body string) events.APIGatewayProxyRequest {
	return events.APIGatewayProxyRequest{Body: body}
}

type lambdaRequest struct {
	Body string
}

func (r lambdaRequest) GetBody() string {
	return r.Body
}
