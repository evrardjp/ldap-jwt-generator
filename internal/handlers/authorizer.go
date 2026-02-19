package handlers

//// If the username and password are correct, then search for the user's group,
//// and only add the user and its group to the request context if successful.
//user, err = authenticator.AuthZ(user)
//if err != nil {
//	// todo, log context r.url.
//	slog.Warn(fmt.Sprintf("user %v failed authorization, logging for auditing purposes, reason:  %v", username, err))
//	http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	return
//}
