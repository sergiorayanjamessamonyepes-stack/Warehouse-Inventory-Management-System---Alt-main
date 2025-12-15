# Remove From Location, To Location, and Reason Fields

## Backend Changes (app.py)
- [ ] Remove fromLocationId, toLocationId, and reason fields from Transaction model
- [ ] Update /api/transactions GET endpoint to exclude these fields
- [ ] Update /api/transactions POST endpoint to not handle these fields
- [ ] Remove logic for transfer and adjustment types that use these fields

## Frontend Changes (TransactionsPage.html)
- [ ] Remove table headers for From Location, To Location, and Reason
- [ ] Update table row rendering to exclude these columns
- [ ] Remove form fields for From Location, To Location, and Reason in modal
- [ ] Update form submission logic to not include these fields
- [ ] Adjust transaction type options if needed

## Testing
- [ ] Test transaction creation for remaining types (receive, issue)
- [ ] Verify table displays correctly
- [ ] Check API responses
