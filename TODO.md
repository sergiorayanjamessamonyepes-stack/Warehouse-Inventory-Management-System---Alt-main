# TODO: Remove fields from Transactions and fix data addition

## Tasks
- [x] Remove fromLocationId, toLocationId, reason fields from Transaction model in app.py (fields not present in current model)
- [x] Update /api/transactions POST route to remove handling of removed fields (removed locationId handling)
- [x] Remove "From Location", "To Location", "Reason", "Location ID" table headers from TransactionsPage.html (headers not present in current table)
- [x] Remove corresponding table data rendering in JS (not present)
- [x] Simplify modal in TransactionsPage.html: remove conditional fields for from/to location, reason (already simplified)
- [x] Update form submission JS to match simplified structure, base on itemspage approach (already matches)
- [x] Test changes: run app, check transactions page functionality (app started successfully, no errors)
