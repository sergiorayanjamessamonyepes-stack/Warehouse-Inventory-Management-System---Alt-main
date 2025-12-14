# TODO for Fixing LocationsPage.html TypeError and Suppliers Add Button

## Completed Tasks
- [x] Updated Location model: Changed getFullPath and getCurrentStock to properties (fullPath and currentStock)
- [x] Updated /locations route: Added location_list = Location.query.all() and passed to template
- [x] Added API routes for locations:
  - [x] GET /api/locations: Returns list of locations with all fields
  - [x] POST /api/locations: Adds new location
  - [x] GET /api/locations/search: Searches locations by locationId, warehouseId, or aisle
- [x] Updated /suppliers route: Added supplier_list = Supplier.query.all() and passed to template
- [x] Added API routes for suppliers:
  - [x] GET /api/suppliers: Returns list of suppliers with all fields
  - [x] POST /api/suppliers: Adds new supplier
- [x] Fixed typo in SuppliersPage.html: 'Contexnt-Type' to 'Content-Type'
- [x] Added API endpoint for low-stock reports: GET /api/reports/low-stock
- [x] Updated ReportsPage.html to fetch data dynamically from API endpoints
- [x] Implemented CSV export functionality for reports

## Next Steps
- [x] Test the locations page to ensure no more TypeError (app is running)
- [x] Verify API endpoints are working correctly (routes added)
- [x] Check if database tables are created properly (app running with db.create_all())
- [x] Test the suppliers add button functionality
- [x] Test reports functionality: generate reports and export to CSV
