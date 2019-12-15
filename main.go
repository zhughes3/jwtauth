package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	appRouter := mux.NewRouter()
	appRouter.HandleFunc("/signin", Signin)
	appRouter.HandleFunc("/welcome", Welcome)
	appRouter.HandleFunc("/refresh", Refresh)

	fs := http.FileServer(http.Dir("public/"))
	appRouter.PathPrefix("/").Handler(http.StripPrefix("/", fs)).Methods("GET")

	server := &http.Server{
		Handler:      appRouter,
		Addr:         ":8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
