package drivertest

//go:generate -command mockgen go run go.uber.org/mock/mockgen@v0.6.0 -package=$GOPACKAGE -typed=true -write_package_comment=false
//go:generate mockgen -destination=update_builder_mock.go -mock_names UpdateBuilder=UpdateBuilder github.com/quay/claircore/updater/driver UpdateBuilder
//go:generate mockgen -destination=advisory_builder_mock.go -mock_names AdvisoryBuilder=AdvisoryBuilder github.com/quay/claircore/updater/driver AdvisoryBuilder
//go:generate mockgen -destination=artifact_builder_mock.go -mock_names ArtifactBuilder=ArtifactBuilder github.com/quay/claircore/updater/driver ArtifactBuilder
