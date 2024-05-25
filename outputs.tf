output "current_public_ip" {
  value = trimspace(data.http.get_public_ip.response_body)
}