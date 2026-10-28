package io.vulscan.core

import com.tngtech.archunit.core.domain.JavaClass
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.junit.AnalyzeClasses
import com.tngtech.archunit.junit.ArchTest
import com.tngtech.archunit.lang.ArchRule
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses

@AnalyzeClasses(packages = ["io.vulscan.core"], importOptions = [ImportOption.DoNotIncludeTests::class])
class ArchitectureTest {

    @ArchTest
    val domainDoesNotDependOnApiOrPersistence: ArchRule =
        noClasses().that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage("..api..", "..persistence..")
            .allowEmptyShould(true)

    @ArchTest
    val apiDoesNotUseRepositoriesDirectly: ArchRule =
        noClasses().that().resideInAPackage("..api..")
            .should().dependOnClassesThat(
                JavaClass.Predicates.resideInAPackage("..persistence..").and(JavaClass.Predicates.simpleNameEndingWith("Repository")),
            )
            .allowEmptyShould(true)

    @ArchTest
    val noDirectHttpClientUsage: ArchRule =
        noClasses().that().resideOutsideOfPackages("io.vulscan.kit..")
            .should().dependOnClassesThat().haveFullyQualifiedName("okhttp3.OkHttpClient")
            .orShould().dependOnClassesThat().resideInAPackage("java.net.http..")
            .allowEmptyShould(true)
}
